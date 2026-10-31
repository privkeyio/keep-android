package io.privkey.keep.storage

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.ShareRegistryRead
import io.privkey.keep.uniffi.ShareStoreStatus
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.Cipher

/**
 * The share registry as the core reads it, and the share file it cannot see: one the
 * registry does not list.
 */
@RunWith(AndroidJUnit4::class)
class ShareRegistryReadTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var storage: AndroidKeystoreStorage
    private lateinit var mobile: KeepMobile
    private val created = mutableSetOf<String>()

    @Before
    fun setup() {
        storage = AndroidKeystoreStorage(context, requireUserAuth = false, keystoreAlias = ALIAS, prefsSuffix = SUFFIX)
        mobile = KeepMobile(storage)
    }

    @After
    fun teardown() {
        created.forEach { group ->
            runCatching { mobile.deleteShareByKey(group) }
            context.deleteSharedPreferences(storage.sharePrefsNameFor(group))
        }
        context.deleteSharedPreferences(MULTI_PREFS)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.aliases().toList().filter { it.startsWith(ALIAS) }.forEach { keyStore.deleteEntry(it) }
    }

    private fun <T> withCipher(cipher: Cipher, block: () -> T): T {
        val requestId = "share-registry-test-${System.nanoTime()}"
        storage.setPendingCipher(requestId, cipher)
        storage.setRequestIdContext(requestId)
        try {
            return block()
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
        }
    }

    private fun import(export: String): String {
        val info = withCipher(storage.getCipherForEncryption()) { mobile.importShare(export, PASSPHRASE, "registry-test") }
        created += info.groupPubkey
        return info.groupPubkey
    }

    private fun groupShares(): List<String> =
        mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "registry-test", PASSPHRASE).shares.map { it.exportData }

    private fun unlist(group: String) {
        val multi = KeystoreEncryptedPrefs.create(context, MULTI_PREFS)
        val keys = multi.getStringSet(ALL_SHARE_KEYS, emptySet()).orEmpty()
        assertTrue(group in keys)
        assertTrue(multi.edit().putStringSet(ALL_SHARE_KEYS, keys - group).commit())
    }

    @Test
    fun aStoredShareReadsAsReadable() {
        val group = import(groupShares().first())

        val read = storage.readShareRegistry() as ShareRegistryRead.Readable
        assertEquals(listOf(group), read.shares.map { it.groupPubkey.toHex() })
        assertEquals(emptyList<String>(), read.unreadable)
        assertEquals(ShareStoreStatus.Readable, mobile.shareStoreStatus())
    }

    // A share whose metadata will not read is listed as unreadable, not dropped, so a
    // backup refuses rather than leave it out.
    @Test
    fun aShareThatWillNotReadIsReportedNotDropped() {
        val group = import(groupShares().first())
        val prefsName = storage.sharePrefsNameFor(group)
        val raw = rawPrefs(context, prefsName)
        val before = raw.all.keys.toSet()
        KeystoreEncryptedPrefs.create(context, prefsName).edit().remove(GROUP_PUBKEY).commit()
        val groupName = (before - raw.all.keys.toSet()).single()
        raw.edit().putString(groupName, "not-a-stored-value").commit()

        val read = storage.readShareRegistry() as ShareRegistryRead.Readable
        assertEquals(emptyList<Any>(), read.shares)
        assertEquals(listOf(group), read.unreadable)
        assertTrue(runCatching { mobile.createBackup(PASSPHRASE) }.isFailure)
    }

    // The core takes a share the registry does not list for an absent one, so neither a
    // restore nor an import of another share of that group may write over it.
    @Test
    fun anUnlistedShareIsNotReplacedByAnotherShareOfItsGroup() {
        val (first, second) = groupShares()
        val group = import(second)
        val backup = withCipher(requireNotNull(storage.getCipherForShareDecryption(group))) { mobile.createBackup(PASSPHRASE) }
        mobile.deleteShareByKey(group)
        assertEquals(group, import(first))
        unlist(group)
        val prefsName = storage.sharePrefsNameFor(group)
        val stored = rawPrefs(context, prefsName).all

        assertTrue(runCatching { withCipher(storage.getCipherForEncryption()) { mobile.importShare(second, PASSPHRASE, "registry-test") } }.isFailure)
        assertEquals(stored, rawPrefs(context, prefsName).all)
        assertTrue(runCatching { withCipher(storage.getCipherForEncryption()) { mobile.restoreBackup(backup, PASSPHRASE) } }.isFailure)
        assertEquals(stored, rawPrefs(context, prefsName).all)
    }

    // The same share again is the write a crash between the data and the registry add
    // leaves to be redone, so it is let through and listed.
    @Test
    fun theSameShareIsWrittenOverItsUnlistedRecordAndListed() {
        val first = groupShares().first()
        val group = import(first)
        unlist(group)

        assertEquals(group, import(first))
        val read = storage.readShareRegistry() as ShareRegistryRead.Readable
        assertEquals(listOf(group), read.shares.map { it.groupPubkey.toHex() })
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private companion object {
        const val SUFFIX = "_share_registry_test"
        const val ALIAS = "keep_frost_share$SUFFIX"
        const val MULTI_PREFS = "keep_multi_share_prefs$SUFFIX"
        const val ALL_SHARE_KEYS = "all_share_keys"
        const val GROUP_PUBKEY = "share_group_pubkey"
        const val PASSPHRASE = "share-registry-test-passphrase"
    }
}
