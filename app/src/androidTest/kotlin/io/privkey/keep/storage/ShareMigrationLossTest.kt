package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
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
    fun a_destination_entry_that_cannot_be_decrypted_is_overwritten_not_trusted() {
        // A name resolving at the destination is not the share being there. This
        // stages an entry that exists and will not open, which a presence check
        // accepts and a read does not.
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

        // The invariant is that the share survives, not that the legacy copy
        // does. An unreadable destination must not authorise the erase on its
        // own, and here it does not: the migration falls through, overwrites the
        // unreadable entry with the real value, and only then clears the source.
        // Asserting the legacy copy lingers would assert the fix had failed.
        assertEquals(
            "the share must be readable somewhere after the migration",
            "legacy-share-bytes",
            sharePrefs().getString("share_data", null)
        )
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
