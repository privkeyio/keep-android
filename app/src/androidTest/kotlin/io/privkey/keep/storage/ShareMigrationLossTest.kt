package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.ShareMetadataInfo
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The legacy share migration copies a share into per-group storage and then
 * erases the source. Every failure in that sequence is unrecoverable if the
 * erase happens without the copy having landed, and it is silent: encrypted
 * prefs return the default when a value cannot be decrypted, and writing that
 * default removes the destination key rather than storing nothing, so the
 * commit reports success having written no share.
 *
 * These stage the two states where that erase could previously happen with no
 * surviving copy, and assert the source is still there afterwards. Losing a
 * share means losing the funds it protects, so the test is about what remains
 * rather than what the function returns.
 */
@RunWith(AndroidJUnit4::class)
class ShareMigrationLossTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before fun setup() = wipe()
    @After fun teardown() = wipe()

    private fun wipe() {
        context.deleteSharedPreferences(LEGACY_PREFS)
        context.deleteSharedPreferences(MULTI_PREFS)
        context.deleteSharedPreferences(shareStoreName())
    }

    private fun legacy() = KeystoreEncryptedPrefs.create(context, LEGACY_PREFS)
    private fun multi() = KeystoreEncryptedPrefs.create(context, MULTI_PREFS)
    private fun sharePrefs() = KeystoreEncryptedPrefs.create(context, shareStoreName())

    /**
     * Mirrors the production derivation. Per-group stores are named from the
     * SHA-256 of the group key, not the key itself, so building the name by
     * concatenation would point the test at a file nothing writes and it would
     * fail for the wrong reason.
     */
    private fun shareStoreName(): String {
        val hash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(GROUP_HEX.toByteArray(Charsets.UTF_8))
        return SHARE_PREFIX + hash.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    /** A legacy share with the metadata the migration needs to derive its group. */
    private fun seedLegacyShare() {
        legacy().edit()
            .putString("share_data", "legacy-share-bytes")
            .putString("share_iv", "legacy-iv")
            .putString("share_name", "mine")
            .putInt("share_index", 1)
            .putInt("share_threshold", 2)
            .putInt("share_total", 3)
            .putString("share_group_pubkey", GROUP_B64)
            .putBoolean("share_did_backup", false)
            .commit()
    }

    @Test
    fun a_group_listed_in_the_registry_with_no_stored_share_is_recovered_not_dropped() {
        // The registry records which groups exist, not whether their data
        // survived. Treating membership as proof of a copy erased the only
        // remaining one. The share must end up somewhere readable; because the
        // copy now succeeds, that somewhere is the per-group store and clearing
        // the legacy copy afterwards is correct rather than a loss.
        seedLegacyShare()
        multi().edit().putStringSet("all_share_keys", setOf(GROUP_HEX)).commit()

        AndroidKeystoreStorage(context, requireUserAuth = false).migrateLegacyShareToRegistrySync()

        assertEquals(
            "the share must be recovered into per-group storage",
            "legacy-share-bytes",
            sharePrefs().getString("share_data", null)
        )
        assertEquals("legacy-iv", sharePrefs().getString("share_iv", null))
    }

    @Test
    fun a_completed_migration_still_clears_the_legacy_copy() {
        // The guard must not turn the migration into a no-op: once the
        // destination holds the share, the source is meant to go.
        seedLegacyShare()

        AndroidKeystoreStorage(context, requireUserAuth = false).migrateLegacyShareToRegistrySync()

        assertEquals(
            "legacy-share-bytes",
            sharePrefs().getString("share_data", null)
        )
        assertEquals(
            "the legacy copy should be gone once the share is stored",
            null,
            legacy().getString("share_data", null)
        )
    }

    @Test
    fun a_share_whose_iv_cannot_be_read_is_not_erased() {
        // The defect this class was written about, which none of the tests
        // above actually staged. A value that will not read back looks exactly
        // like an absent one, and writing that absence removes the destination
        // key, so the copy "succeeds" having written nothing and the source is
        // erased. Staged by omitting the iv, which is the same shape as a read
        // that failed.
        legacy().edit()
            .putString("share_data", "legacy-share-bytes")
            .putString("share_name", "mine")
            .putInt("share_index", 1)
            .putInt("share_threshold", 2)
            .putInt("share_total", 3)
            .putString("share_group_pubkey", GROUP_B64)
            .putBoolean("share_did_backup", false)
            .commit()

        AndroidKeystoreStorage(context, requireUserAuth = false).migrateLegacyShareToRegistrySync()

        assertNotNull(
            "an incomplete share must stay where it is rather than being erased",
            legacy().getString("share_data", null)
        )
    }

    @Test
    fun a_destination_entry_that_cannot_be_decrypted_is_neither_trusted_nor_overwritten() {
        // A name resolving at the destination is not the share being there, and an
        // entry that will not open may be another share hit by a transient fault.
        // This stages one that exists and will not open.
        seedLegacyShare()
        val dest = context.getSharedPreferences(shareStoreName(), Context.MODE_PRIVATE)
        // Identify share_data's entry by what writing it adds. Filtering on the
        // value prefix would also match the derivation key and the registry, and
        // corrupting the derivation key throws out of the read path instead of
        // exercising the guard under test.
        sharePrefs().edit().putString("anchor", "0").commit()
        val before = dest.all.keys.toSet()
        sharePrefs().edit().putString("share_data", "placeholder").commit()
        val added = dest.all.keys.toSet() - before
        assertEquals("expected exactly one new stored entry", 1, added.size)
        // Keep it decodable as base64 so the failure is an authentication
        // failure rather than a malformed-input throw.
        dest.edit().putString(added.first(), "v2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").commit()

        AndroidKeystoreStorage(context, requireUserAuth = false).migrateLegacyShareToRegistrySync()

        // Neither copy may be destroyed: the legacy share stays where it is and the
        // unreadable entry is not overwritten, so a later start can still read it.
        assertEquals(
            "the legacy share must survive",
            "legacy-share-bytes",
            legacy().getString("share_data", null)
        )
        assertEquals(
            "the unreadable entry must not be overwritten",
            "v2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            dest.getString(added.first(), null)
        )
    }

    @Test
    fun another_share_of_the_group_in_per_group_storage_does_not_erase_the_legacy_share() {
        // A legacy share (index 1) that did not migrate, then index 2 of the same group
        // imported into the group's store. Both are needed to sign, so the legacy one
        // must survive the next migration rather than be cleared as already moved.
        seedLegacyShare()
        sharePrefs().edit()
            .putString("share_data", "imported-share-bytes")
            .putString("share_iv", "imported-iv")
            .putInt("share_index", 2)
            .commit()

        // Run twice, as on two starts: the kept state is stable and writes nothing more.
        AndroidKeystoreStorage(context, requireUserAuth = false).migrateLegacyShareToRegistrySync()
        AndroidKeystoreStorage(context, requireUserAuth = false).migrateLegacyShareToRegistrySync()

        assertEquals("legacy-share-bytes", legacy().getString("share_data", null))
        assertEquals("imported-share-bytes", sharePrefs().getString("share_data", null))
        assertEquals(setOf(GROUP_HEX), multi().getStringSet("all_share_keys", null))
    }

    @Test
    fun a_stored_share_with_no_index_does_not_erase_the_legacy_share() {
        // Without an index there is no proof the stored share is this one.
        seedLegacyShare()
        sharePrefs().edit()
            .putString("share_data", "imported-share-bytes")
            .putString("share_iv", "imported-iv")
            .commit()

        AndroidKeystoreStorage(context, requireUserAuth = false).migrateLegacyShareToRegistrySync()

        assertEquals("legacy-share-bytes", legacy().getString("share_data", null))
        assertEquals("imported-share-bytes", sharePrefs().getString("share_data", null))
    }

    @Test
    fun a_kept_legacy_share_does_not_take_the_cipher_from_the_active_share() {
        // With the legacy share kept beside another share of its group, signing still
        // decrypts the active share, so the cipher handed to the core must be its own
        // and not one built from the legacy key and iv.
        seedLegacyShare()
        val storage = AndroidKeystoreStorage(context, requireUserAuth = false)
        storage.storeShareByKeyWithCipher(
            storage.getCipherForShareEncryption(GROUP_HEX),
            GROUP_HEX,
            "imported-share-bytes".toByteArray(),
            ShareMetadataInfo("other", 2u, 2u, 3u, ByteArray(32), false)
        )
        storage.setActiveShareKey(GROUP_HEX)
        storage.migrateLegacyShareToRegistrySync()
        assertNotNull("the legacy share must be kept", legacy().getString("share_data", null))

        val cipher = storage.getCipherForDecryption()
        val active = storage.getCipherForShareDecryption(GROUP_HEX)
        assertNotNull(cipher)
        assertNotNull(active)
        assertArrayEquals(active!!.iv, cipher!!.iv)
        assertEquals("the active share is described", 2, storage.getShareMetadata()?.identifier?.toInt())
    }

    @Test
    fun the_same_share_already_in_per_group_storage_clears_the_legacy_copy() {
        // A migration that stored the share but stopped before clearing the source.
        seedLegacyShare()
        sharePrefs().edit()
            .putString("share_data", "legacy-share-bytes")
            .putString("share_iv", "legacy-iv")
            .putInt("share_index", 1)
            .commit()

        AndroidKeystoreStorage(context, requireUserAuth = false).migrateLegacyShareToRegistrySync()

        assertEquals(null, legacy().getString("share_data", null))
        assertEquals("legacy-share-bytes", sharePrefs().getString("share_data", null))
    }

    companion object {
        private const val LEGACY_PREFS = "keep_secure_prefs"
        private const val MULTI_PREFS = "keep_multi_share_prefs"
        private const val SHARE_PREFIX = "keep_share_"
        // 32 zero bytes; the migration derives the group hex from these.
        private const val GROUP_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        private const val GROUP_HEX = "0000000000000000000000000000000000000000000000000000000000000000"
    }
}
