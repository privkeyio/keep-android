package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.ShareMetadataInfo
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Both of these stores replace a whole stored entry on write, and both read that entry
 * first. Reading it as empty when it cannot be decrypted turns the write that follows
 * into a delete of everything the entry held, which is why neither can treat an
 * unreadable value as an absent one.
 *
 * The fault is staged on disk rather than injected, so what these assert is that the
 * stored ciphertext is still there afterwards.
 */
@RunWith(AndroidJUnit4::class)
class UnreadableReadGuardTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before fun setup() = clear()
    @After fun teardown() = clear()

    private fun clear() {
        context.deleteSharedPreferences(AUDIT_PREFS)
        context.deleteSharedPreferences(WHITELIST_PREFS)
        // The share files too: a corrupted registry left behind would make the next
        // test's first write hit the very guard under test, before it staged anything.
        context.deleteSharedPreferences(SHARE_REGISTRY_PREFS)
        context.deleteSharedPreferences("keep_secure_prefs$SHARE_SUFFIX")
        listOf(FIRST_GROUP, SECOND_GROUP, THIRD_GROUP).forEach {
            context.deleteSharedPreferences(shareStoreName(it))
        }
    }

    /** Mirrors the production derivation: a per-share file is named from the key's hash. */
    private fun shareStoreName(group: String): String {
        val hash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(group.toByteArray(Charsets.UTF_8))
        return "keep_share_" + hash.joinToString("") { "%02x".format(it.toInt() and 0xFF) } + SHARE_SUFFIX
    }

    @Test
    fun an_unreadable_audit_log_is_reported_rather_than_read_as_empty() {
        val storage = AndroidAuditStorage(context)
        val storedName = writeAndFindStoredName(context, AUDIT_PREFS) {
            storage.storeEntry(FIRST_ENTRY)
        }
        assertEquals(1, storage.loadEntries(null).size)

        corruptStoredValue(context, AUDIT_PREFS, storedName)

        assertThrows(KeepMobileException.StorageException::class.java) {
            AndroidAuditStorage(context).loadEntries(null)
        }
    }

    @Test
    fun storing_an_entry_does_not_overwrite_an_audit_log_it_could_not_read() {
        // The whole point. The log is tamper evident, so a truncation that reports
        // success is worse than a failure: the chain would restart with nothing saying
        // it had.
        val storage = AndroidAuditStorage(context)
        val storedName = writeAndFindStoredName(context, AUDIT_PREFS) {
            storage.storeEntry(FIRST_ENTRY)
        }
        corruptStoredValue(context, AUDIT_PREFS, storedName)
        val corrupted = rawPrefs(context, AUDIT_PREFS).getString(storedName, null)

        assertThrows(KeepMobileException.StorageException::class.java) {
            AndroidAuditStorage(context).storeEntry(SECOND_ENTRY)
        }

        assertEquals(
            "the stored log must be exactly as it was, not replaced by the new entry",
            corrupted,
            rawPrefs(context, AUDIT_PREFS).getString(storedName, null)
        )
    }

    @Test
    fun adding_a_relay_host_does_not_replace_a_whitelist_it_could_not_read() {
        // An empty read here would write back a list holding only the host being added,
        // and the list is a hard gate: every other relay the person allowed would start
        // being auto-rejected.
        val store = RelayAuthWhitelistStore(context)
        val storedName = writeAndFindStoredName(context, WHITELIST_PREFS) {
            assertNotNull(store.add("wss://relay.example.com"))
        }
        corruptStoredValue(context, WHITELIST_PREFS, storedName)
        val corrupted = rawPrefs(context, WHITELIST_PREFS).getString(storedName, null)

        assertNull(
            "an add over an unreadable list must fail rather than replace it",
            RelayAuthWhitelistStore(context).add("wss://other.example.com")
        )

        assertEquals(
            "the stored whitelist must be exactly as it was",
            corrupted,
            rawPrefs(context, WHITELIST_PREFS).getString(storedName, null)
        )
    }

    @Test
    fun removing_a_relay_host_does_not_write_back_a_whitelist_it_could_not_read() {
        val store = RelayAuthWhitelistStore(context)
        val storedName = writeAndFindStoredName(context, WHITELIST_PREFS) {
            assertNotNull(store.add("wss://relay.example.com"))
        }
        corruptStoredValue(context, WHITELIST_PREFS, storedName)
        val corrupted = rawPrefs(context, WHITELIST_PREFS).getString(storedName, null)

        RelayAuthWhitelistStore(context).remove("relay.example.com")

        assertEquals(
            "a remove over an unreadable list must not write anything",
            corrupted,
            rawPrefs(context, WHITELIST_PREFS).getString(storedName, null)
        )
    }

    @Test
    fun clearing_an_unreadable_audit_log_lets_writing_resume() {
        // The escape hatch. Without it an unreadable log refuses every read and write
        // for good, so this pins that a clear actually recovers the store.
        val seeded = AndroidAuditStorage(context)
        val storedName = writeAndFindStoredName(context, AUDIT_PREFS) {
            seeded.storeEntry(FIRST_ENTRY)
        }
        corruptStoredValue(context, AUDIT_PREFS, storedName)

        AndroidAuditStorage(context).clearEntries()

        val storage = AndroidAuditStorage(context)
        storage.storeEntry(SECOND_ENTRY)
        assertEquals(listOf(SECOND_ENTRY), storage.loadEntries(null))
    }

    @Test
    fun a_fresh_audit_log_loads_empty_rather_than_failing() {
        // Absent is still absent: the guard must not turn a store nobody has written
        // into an error.
        assertEquals(emptyList<String>(), AndroidAuditStorage(context).loadEntries(null))
    }

    @Test
    fun an_unreadable_registry_does_not_deregister_the_other_share_groups() {
        // The write replaces the whole registry, so an empty read would persist a set
        // holding only the group being added. The other groups' share files survive
        // while vanishing from listing, the active-share lookup and the backup gate.
        val storage = shareStorage()
        // The registry entry appears on the first share, so that is the write whose
        // stored name identifies it; the second share updates the same entry.
        val storedName = writeAndFindStoredName(context, SHARE_REGISTRY_PREFS) {
            seedShare(storage, FIRST_GROUP, 1)
        }
        seedShare(storage, SECOND_GROUP, 2)
        corruptStoredValue(context, SHARE_REGISTRY_PREFS, storedName)
        val corrupted = rawPrefs(context, SHARE_REGISTRY_PREFS).getString(storedName, null)

        assertThrows(KeepMobileException.StorageException::class.java) {
            shareStorage().let { seedShare(it, THIRD_GROUP, 3) }
        }

        assertEquals(
            "the registry must be exactly as it was, not replaced by the new group",
            corrupted,
            rawPrefs(context, SHARE_REGISTRY_PREFS).getString(storedName, null)
        )
    }

    @Test
    fun deleting_a_share_does_not_deregister_the_others_from_an_unreadable_registry() {
        val storage = shareStorage()
        // The registry entry appears on the first share, so that is the write whose
        // stored name identifies it; the second share updates the same entry.
        val storedName = writeAndFindStoredName(context, SHARE_REGISTRY_PREFS) {
            seedShare(storage, FIRST_GROUP, 1)
        }
        seedShare(storage, SECOND_GROUP, 2)
        corruptStoredValue(context, SHARE_REGISTRY_PREFS, storedName)
        val corrupted = rawPrefs(context, SHARE_REGISTRY_PREFS).getString(storedName, null)

        assertThrows(KeepMobileException.StorageException::class.java) {
            shareStorage().deleteShareByKey(SECOND_GROUP)
        }

        assertEquals(
            corrupted,
            rawPrefs(context, SHARE_REGISTRY_PREFS).getString(storedName, null)
        )
    }

    @Test
    fun a_refused_delete_leaves_the_share_data_in_place() {
        // The registry is read before anything is destroyed, so a delete that cannot
        // complete leaves the account intact rather than removing the share and then
        // reporting failure with its registry entry still listed.
        val storage = shareStorage()
        val storedName = writeAndFindStoredName(context, SHARE_REGISTRY_PREFS) {
            seedShare(storage, FIRST_GROUP, 1)
        }
        seedShare(storage, SECOND_GROUP, 2)
        corruptStoredValue(context, SHARE_REGISTRY_PREFS, storedName)

        assertThrows(KeepMobileException.StorageException::class.java) {
            shareStorage().deleteShareByKey(SECOND_GROUP)
        }

        assertTrue(
            "the share data must survive a delete that could not finish",
            rawPrefs(context, shareStoreName(SECOND_GROUP)).all.isNotEmpty()
        )
    }

    @Test
    fun an_unreadable_registry_leaves_the_active_share_pointer_alone() {
        // hasShare clears the pointer when the registry looks empty, and it is one of
        // the methods that cannot report a fault, so an unreadable registry has to stop
        // short of that write rather than be read as "no shares".
        val storage = shareStorage()
        val storedName = writeAndFindStoredName(context, SHARE_REGISTRY_PREFS) {
            seedShare(storage, FIRST_GROUP, 1)
        }
        seedShare(storage, SECOND_GROUP, 2)
        storage.setActiveShareKey(FIRST_GROUP)
        corruptStoredValue(context, SHARE_REGISTRY_PREFS, storedName)

        val fresh = shareStorage()
        assertTrue("an unreadable registry must not report an empty store", fresh.hasShare())
        assertEquals(
            "the active pointer must survive a registry it could not read",
            FIRST_GROUP,
            fresh.getActiveShareKey()
        )
    }

    @Test
    fun a_readable_whitelist_still_accepts_a_host() {
        // The guard must not cost the ordinary path: absent is still a first use.
        val store = RelayAuthWhitelistStore(context)

        assertEquals("relay.example.com", store.add("wss://relay.example.com"))
        assertEquals("other.example.com", store.add("wss://other.example.com"))

        assertEquals(listOf("other.example.com", "relay.example.com"), store.hosts())
    }

    private fun shareStorage() = AndroidKeystoreStorage(
        context,
        requireUserAuth = false,
        keystoreAlias = "keep_frost_share$SHARE_SUFFIX",
        prefsSuffix = SHARE_SUFFIX
    )

    /**
     * Writes a share through the real encrypt path, which is what registers its group.
     * [AndroidKeystoreStorage.storeShareByKey] cannot be used here: it demands a request
     * context and an authenticated cipher, which needs an enrolled biometric.
     */
    private fun seedShare(storage: AndroidKeystoreStorage, group: String, index: Int) {
        val cipher = storage.getCipherForShareEncryption(group)
        storage.storeShareByKeyWithCipher(cipher, group, byteArrayOf(index.toByte()), metadata(index))
    }

    private fun metadata(index: Int) = ShareMetadataInfo(
        name = "account $index",
        identifier = index.toUShort(),
        threshold = 2u,
        totalShares = 3u,
        groupPubkey = ByteArray(32) { index.toByte() },
        didBackup = false
    )

    private companion object {
        const val AUDIT_PREFS = "keep_audit_log"
        const val WHITELIST_PREFS = RelayAuthWhitelistStore.PREFS_NAME
        const val SHARE_SUFFIX = "_unreadable_read_guard_test"
        const val SHARE_REGISTRY_PREFS = "keep_multi_share_prefs$SHARE_SUFFIX"
        const val FIRST_ENTRY = "{\"event\":\"first\"}"
        const val SECOND_ENTRY = "{\"event\":\"after\"}"
        const val FIRST_GROUP = "1111111111111111111111111111111111111111111111111111111111111111"
        const val SECOND_GROUP = "2222222222222222222222222222222222222222222222222222222222222222"
        const val THIRD_GROUP = "3333333333333333333333333333333333333333333333333333333333333333"
    }
}
