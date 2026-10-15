package io.privkey.keep.storage

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.KeepMobileException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * uniffi generates `hasShare`, `getShareMetadata`, `listAllShares` and
 * `getActiveShareKey` without an error type, so a throw from one of them is an
 * unexpected-callback error rather than a storage error the core can act on, and the
 * core panics on it. They are not fault-free: resolving a key name goes through the
 * file's HMAC key, whose decrypt is unguarded, so an entry that no longer decrypts
 * raises out of `contains` and out of every typed getter.
 *
 * These corrupt that one entry, which is the fault the production path reaches when a
 * Keystore alias no longer matches what is stored, and assert each method answers
 * instead of raising. `hasShare` is asserted to answer `true`: the no-account UI is
 * driven from it and offers an import that writes the single-share slot, so "no share"
 * would invite overwriting a share that is only unreadable.
 */
@RunWith(AndroidJUnit4::class)
class InfallibleStorageReadTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before fun setup() = wipe()
    @After fun teardown() = wipe()

    private fun wipe() {
        context.deleteSharedPreferences(SINGLE_PREFS + SUFFIX)
        context.deleteSharedPreferences(MULTI_PREFS + SUFFIX)
        context.deleteSharedPreferences(shareStoreName() + SUFFIX)
        context.deleteSharedPreferences(shareStoreName(SECOND_GROUP_HEX) + SUFFIX)
    }

    /**
     * Mirrors the production derivation: a registry name resolves to a per-share file
     * named from the SHA-256 of the key, so seeding only the legacy slot leaves every
     * registry entry unresolvable and the share list empty.
     */
    private fun shareStoreName(groupHex: String = GROUP_HEX): String {
        val hash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(groupHex.toByteArray(Charsets.UTF_8))
        return SHARE_PREFIX + hash.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    private fun storage() = AndroidKeystoreStorage(
        context,
        requireUserAuth = false,
        keystoreAlias = "keep_frost_share$SUFFIX",
        prefsSuffix = SUFFIX
    )

    /** A share in the legacy slot and one name in the registry, both readable. */
    private fun seedReadableStore() {
        KeystoreEncryptedPrefs.create(context, SINGLE_PREFS + SUFFIX).edit()
            .putString("share_data", "share-bytes")
            .putString("share_iv", "iv")
            .putString("share_name", "account")
            .putInt("share_index", 1)
            .putInt("share_threshold", 2)
            .putInt("share_total", 3)
            .putString("share_group_pubkey", GROUP_B64)
            .commit()
        seedShareFile(GROUP_HEX, GROUP_B64)
        KeystoreEncryptedPrefs.create(context, MULTI_PREFS + SUFFIX).edit()
            .putStringSet("all_share_keys", setOf(GROUP_HEX))
            .putString("active_share_key", GROUP_HEX)
            .commit()
    }

    /** One share in its own per-group file, named the way production names it. */
    private fun seedShareFile(groupHex: String, groupB64: String) {
        KeystoreEncryptedPrefs.create(context, shareStoreName(groupHex) + SUFFIX).edit()
            .putString("share_data", "share-bytes")
            .putString("share_iv", "iv")
            .putString("share_name", "account")
            .putInt("share_index", 1)
            .putInt("share_threshold", 2)
            .putInt("share_total", 3)
            .putString("share_group_pubkey", groupB64)
            .commit()
    }

    /**
     * Two shares in the registry with the first one's file unreadable, and no legacy
     * slot, so a read has to resolve each share on its own.
     */
    private fun seedTwoSharesWithTheFirstUnreadable(activeKey: String?) {
        seedShareFile(GROUP_HEX, GROUP_B64)
        seedShareFile(SECOND_GROUP_HEX, SECOND_GROUP_B64)
        KeystoreEncryptedPrefs.create(context, MULTI_PREFS + SUFFIX).edit()
            .putStringSet("all_share_keys", setOf(GROUP_HEX, SECOND_GROUP_HEX))
            .apply { if (activeKey != null) putString("active_share_key", activeKey) }
            .commit()
        breakNameResolution(shareStoreName(GROUP_HEX) + SUFFIX)
    }

    /**
     * Breaks name resolution for one file the way production breaks it.
     *
     * The HMAC key is read from the raw prefs and decrypted with the file's Keystore
     * key, with nothing catching a failure, so a value that cannot decrypt makes every
     * lookup in that file raise. The stored entry's last byte is flipped rather than
     * replaced with junk: that keeps a well-formed IV and body so the failure is the
     * GCM tag check, which is what a Keystore alias that no longer matches produces.
     * Replacing it with a short string instead raises out of the IV slice, a different
     * branch that would not prove the realistic fault is handled.
     */
    private fun breakNameResolution(prefsName: String) {
        val raw = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
        val stored = raw.getString(HMAC_KEY, null)
        assertNotNull("the file must already hold an HMAC key to corrupt", stored)
        val bytes = Base64.decode(stored!!.removePrefix(BOUND_PREFIX), Base64.NO_WRAP)
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
        val corrupted = Base64.encodeToString(bytes, Base64.NO_WRAP)
        raw.edit()
            .putString(HMAC_KEY, if (stored.startsWith(BOUND_PREFIX)) BOUND_PREFIX + corrupted else corrupted)
            .commit()
    }

    @Test
    fun a_readable_store_answers_normally() {
        // Without this the fault assertions could pass on an empty store and prove
        // nothing: each one below has to flip an answer that was different when the
        // same call could still resolve its key names.
        seedReadableStore()
        val storage = storage()

        assertTrue("a seeded store has a share", storage.hasShare())
        assertNotNull("the seeded metadata reads back", storage.getShareMetadata())
        assertEquals("the registry lists the seeded share", 1, storage.listAllShares().size)
        assertEquals("the seeded share is active", GROUP_HEX, storage.getActiveShareKey())
    }

    @Test
    fun metadata_resolves_through_the_registry_when_the_legacy_slot_is_empty() {
        // The branch the guard rewrote. With the legacy slot populated the method
        // returns before ever reaching it, so without this the registry half of
        // getShareMetadata has no coverage at all.
        seedShareFile(GROUP_HEX, GROUP_B64)
        KeystoreEncryptedPrefs.create(context, MULTI_PREFS + SUFFIX).edit()
            .putStringSet("all_share_keys", setOf(GROUP_HEX))
            .putString("active_share_key", GROUP_HEX)
            .commit()

        assertNotNull(
            "metadata must resolve through the active registry key",
            storage().getShareMetadata()
        )
    }

    @Test
    fun one_unreadable_share_does_not_hide_the_readable_ones() {
        // The guard has to be per share, not per call. Every share has its own file
        // under its own Keystore alias, so guarding only the method turns one
        // unreadable share into an empty list and a null active key, which is the
        // same answer as owning no shares at all.
        seedTwoSharesWithTheFirstUnreadable(activeKey = GROUP_HEX)

        val listed = storage().listAllShares()
        assertEquals("the readable share must still be listed: $listed", 1, listed.size)
    }

    @Test
    fun an_unreadable_share_does_not_block_selecting_a_readable_active_one() {
        // Separate from the list assertion above so each half of the per-share guard
        // is proven on its own. No stored pointer, so this is the fallback scan: it
        // reaches the unreadable share first and has to survive it to find the
        // readable one.
        seedTwoSharesWithTheFirstUnreadable(activeKey = null)

        assertEquals(
            "a readable share must still be selectable as active",
            SECOND_GROUP_HEX,
            storage().getActiveShareKey()
        )
    }

    @Test
    fun an_unreadable_active_share_is_not_silently_swapped_for_a_readable_one() {
        // The opposite answer, and the reason the fault value is per caller. The
        // active account is the one the stored pointer names; treating "cannot read
        // it" as "it is gone" would sign as a different account while NIP-55 grants
        // are keyed on the calling package alone and survive the switch.
        seedTwoSharesWithTheFirstUnreadable(activeKey = GROUP_HEX)

        assertEquals(
            "the active account must not change because its share cannot be read",
            GROUP_HEX,
            storage().getActiveShareKey()
        )
    }

    @Test
    fun a_fallible_method_reports_a_storage_error_rather_than_a_crypto_exception() {
        // uniffi lowers only the declared error, so a raw crypto exception out of a
        // fallible method is the same unexpected-callback error that panics the core.
        seedReadableStore()
        breakNameResolution(MULTI_PREFS + SUFFIX)

        try {
            storage().setActiveShareKey(GROUP_HEX)
            throw AssertionError("a write through an unreadable registry must not succeed")
        } catch (e: KeepMobileException.StorageException) {
            // The declared error, which the core can act on.
        }
    }

    @Test
    fun a_migration_does_not_repoint_the_active_account_on_a_fault() {
        // The stored pointer names the active account. Resolving it through
        // getActiveShareKey() would read a swallowed fault as "nothing is active" and
        // move the account out from under the NIP-55 grants.
        seedShareFile(SECOND_GROUP_HEX, SECOND_GROUP_B64)
        KeystoreEncryptedPrefs.create(context, MULTI_PREFS + SUFFIX).edit()
            .putStringSet("all_share_keys", setOf(SECOND_GROUP_HEX))
            .putString("active_share_key", SECOND_GROUP_HEX)
            .commit()
        breakNameResolution(shareStoreName(SECOND_GROUP_HEX) + SUFFIX)
        KeystoreEncryptedPrefs.create(context, SINGLE_PREFS + SUFFIX).edit()
            .putString("share_data", "share-bytes")
            .putString("share_iv", "iv")
            .putString("share_name", "account")
            .putInt("share_index", 1)
            .putInt("share_threshold", 2)
            .putInt("share_total", 3)
            .putString("share_group_pubkey", GROUP_B64)
            .commit()

        storage().migrateLegacyShareToRegistrySync()

        assertEquals(
            "the active account must survive a migration that cannot read it",
            SECOND_GROUP_HEX,
            KeystoreEncryptedPrefs.create(context, MULTI_PREFS + SUFFIX)
                .getString("active_share_key", null)
        )
    }

    @Test
    fun an_unreadable_active_share_does_not_report_an_empty_store() {
        // The same fault reached through hasShare, which answers a different
        // question: whether a share might exist, where a fault has to count as yes.
        seedTwoSharesWithTheFirstUnreadable(activeKey = GROUP_HEX)

        assertTrue(storage().hasShare())
    }

    @Test
    fun an_unreadable_single_share_file_still_reports_that_a_share_exists() {
        seedReadableStore()
        breakNameResolution(SINGLE_PREFS + SUFFIX)

        // Pre-fix this raised the GCM tag failure out of an infallible callback.
        assertTrue(
            "a fault must not read as 'no share': the no-account UI offers an import " +
                "that overwrites the slot this share is in",
            storage().hasShare()
        )
    }

    @Test
    fun an_unreadable_registry_resolves_every_infallible_read() {
        seedReadableStore()
        breakNameResolution(SINGLE_PREFS + SUFFIX)
        breakNameResolution(MULTI_PREFS + SUFFIX)
        val storage = storage()

        assertTrue("still reports a share", storage.hasShare())
        assertNull("metadata resolves rather than raising", storage.getShareMetadata())
        assertEquals("the share list resolves rather than raising", emptyList<Any>(), storage.listAllShares())
        assertNull("the active key resolves rather than raising", storage.getActiveShareKey())
    }

    @Test
    fun an_unreadable_share_makes_the_store_report_itself_as_not_fully_readable() {
        // What the backup path gates on. The share list silently drops the unreadable
        // share, so a backup built from it would hold one share for a device that
        // owns two, encrypt, save and report success.
        seedTwoSharesWithTheFirstUnreadable(activeKey = GROUP_HEX)
        val storage = storage()

        assertEquals("precondition: the list is short, not empty", 1, storage.listAllShares().size)
        assertFalse(
            "a store with an unreadable share must not report itself fully readable",
            storage.shareStorageIsFullyReadable()
        )
    }

    @Test
    fun an_unreadable_registry_also_reports_as_not_fully_readable() {
        seedReadableStore()
        breakNameResolution(MULTI_PREFS + SUFFIX)

        assertFalse(storage().shareStorageIsFullyReadable())
    }

    @Test
    fun a_healthy_store_reports_itself_fully_readable() {
        seedReadableStore()

        assertTrue(storage().shareStorageIsFullyReadable())
    }

    @Test
    fun a_registry_key_that_was_never_stored_does_not_count_as_unreadable() {
        // Absent is not unreadable. Counting it would block backups for good on a
        // store that has a dangling registry entry, which is a state the migration
        // tests already stage.
        KeystoreEncryptedPrefs.create(context, MULTI_PREFS + SUFFIX).edit()
            .putStringSet("all_share_keys", setOf(GROUP_HEX))
            .commit()

        assertTrue(storage().shareStorageIsFullyReadable())
    }

    @Test
    fun a_share_the_list_drops_for_unusable_metadata_is_not_fully_readable() {
        // The fault that drops a share here is metadata that will not turn into a
        // share rather than metadata that will not decrypt: an undecryptable value
        // reads back as its default, while an index outside UShort range fails
        // readMetadataFromPrefs' own range check and answers null. listAllShares
        // drops the share either way, so checking that the share data is present
        // would pass a store whose backup silently omits a share.
        seedShareFile(GROUP_HEX, GROUP_B64)
        seedShareFile(SECOND_GROUP_HEX, SECOND_GROUP_B64)
        KeystoreEncryptedPrefs.create(context, shareStoreName(SECOND_GROUP_HEX) + SUFFIX).edit()
            .putInt("share_index", UShort.MAX_VALUE.toInt() + 1)
            .commit()
        KeystoreEncryptedPrefs.create(context, MULTI_PREFS + SUFFIX).edit()
            .putStringSet("all_share_keys", setOf(GROUP_HEX, SECOND_GROUP_HEX))
            .commit()

        val storage = storage()
        assertEquals(
            "precondition: the share is missing from the list a backup is built from",
            1,
            storage.listAllShares().size
        )
        assertFalse(storage.shareStorageIsFullyReadable())
    }

    private companion object {
        const val SINGLE_PREFS = "keep_secure_prefs"
        const val MULTI_PREFS = "keep_multi_share_prefs"
        const val SHARE_PREFIX = "keep_share_"
        const val HMAC_KEY = "__hmac_key__"
        // The marker KeystoreEncryptedPrefs puts on a value bound to its key name.
        const val BOUND_PREFIX = "v2:"
        const val SUFFIX = "_infallible_read_test"
        const val GROUP_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        const val GROUP_HEX = "0000000000000000000000000000000000000000000000000000000000000000"
        // Sorts after GROUP_HEX, so the unreadable share is the one the fallback
        // scan reaches first and the scan has to survive it to find this one.
        const val SECOND_GROUP_HEX = "1111111111111111111111111111111111111111111111111111111111111111"
        const val SECOND_GROUP_B64 = "ERERERERERERERERERERERERERERERERERERERERERE="
    }
}
