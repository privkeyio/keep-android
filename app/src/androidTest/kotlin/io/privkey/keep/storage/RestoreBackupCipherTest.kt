package io.privkey.keep.storage

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.uniffi.KeepMobile
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.Cipher

/**
 * Restores a backup the way the backup screen does: one cipher staged for the request.
 * A backup is made with the cipher that decrypts the active share, and a restore with
 * one that encrypts under the default key, as an import is.
 */
@RunWith(AndroidJUnit4::class)
class RestoreBackupCipherTest {

    private lateinit var storage: AndroidKeystoreStorage
    private lateinit var mobile: KeepMobile
    private val created = mutableListOf<String>()

    @Before
    fun setup() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        storage = AndroidKeystoreStorage(context, requireUserAuth = false, keystoreAlias = ALIAS, prefsSuffix = SUFFIX)
        mobile = KeepMobile(storage)
    }

    @After
    fun teardown() {
        created.forEach { runCatching { mobile.deleteShareByKey(it) } }
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.aliases().toList().filter { it.startsWith(ALIAS) }.forEach { keyStore.deleteEntry(it) }
    }

    private fun <T> withCipher(cipher: Cipher, block: () -> T): T {
        val requestId = "restore-cipher-test-${System.nanoTime()}"
        storage.setPendingCipher(requestId, cipher)
        storage.setRequestIdContext(requestId)
        try {
            return block()
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
        }
    }

    private fun importNewGroup(): String {
        val export = mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "restore-test", "restore-test")
            .shares.first().exportData
        val info = withCipher(storage.getCipherForEncryption()) {
            mobile.importShare(export, "restore-test", "restore-test")
        }
        created += info.groupPubkey
        return info.groupPubkey
    }

    private fun storedGroups(): List<String> =
        storage.listAllShares().map { meta -> meta.groupPubkey.joinToString("") { "%02x".format(it) } }

    private fun backupCipher(): Cipher {
        val key = storage.getActiveShareKey()
        return requireNotNull(if (key != null) storage.getCipherForShareDecryption(key) else storage.getCipherForDecryption()) {
            "the backup screen would refuse with no cipher"
        }
    }

    @Test
    fun aBackupRestoresOntoADeviceThatHoldsAnotherShare() {
        val backedUp = importNewGroup()
        val original = loadShare(backedUp)
        val backup = withCipher(backupCipher()) { mobile.createBackup(PASSPHRASE) }
        importNewGroup()
        mobile.deleteShareByKey(backedUp)
        assertTrue(backedUp !in storedGroups())

        val info = withCipher(storage.getCipherForEncryption()) { mobile.restoreBackup(backup, PASSPHRASE) }

        assertEquals(1u, info.shareCount)
        assertTrue("the restored share must be listed", backedUp in storedGroups())
        assertTrue("and read back as it was", original.contentEquals(loadShare(backedUp)))
    }

    // A group still on the device is refused, and its share is left as it was.
    @Test
    fun aRestoreOverAStoredShareIsRefused() {
        val group = importNewGroup()
        val original = loadShare(group)
        val backup = withCipher(backupCipher()) { mobile.createBackup(PASSPHRASE) }

        assertTrue(runCatching { withCipher(storage.getCipherForEncryption()) { mobile.restoreBackup(backup, PASSPHRASE) } }.isFailure)
        assertTrue("the share must be untouched", original.contentEquals(loadShare(group)))
    }

    // A share that is stored and will not read is not absent: the restore must not
    // be told it is and write over it.
    @Test
    fun aRestoreDoesNotWriteOverAShareThatWillNotRead() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val group = importNewGroup()
        val backup = withCipher(backupCipher()) { mobile.createBackup(PASSPHRASE) }
        val prefsName = storage.sharePrefsNameFor(group)
        // Moved to the name any build can derive and broken there, where a value that
        // fails to decrypt is refused rather than read as unreadable.
        val raw = rawPrefs(context, prefsName)
        val namesBefore = raw.all.keys.toSet()
        val storedValues = raw.all
        KeystoreEncryptedPrefs.create(context, prefsName).edit().remove(SHARE_DATA).commit()
        val storedName = (namesBefore - raw.all.keys.toSet()).single()
        val fallback = fallbackNameIn(prefsName, SHARE_DATA)
        raw.edit().putString(fallback, storedValues[storedName] as String).commit()
        corruptStoredValue(context, prefsName, fallback)
        val before = rawPrefs(context, prefsName).all

        runCatching { withCipher(storage.getCipherForEncryption()) { mobile.restoreBackup(backup, PASSPHRASE) } }

        assertEquals("the unreadable record must be left as it was", before, rawPrefs(context, prefsName).all)
    }

    private fun <T> withCiphers(stage: (String) -> Unit, block: () -> T): T {
        val requestId = "restore-cipher-test-${System.nanoTime()}"
        stage(requestId)
        storage.setRequestIdContext(requestId)
        try {
            return block()
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
            storage.clearCipherProvider(requestId)
        }
    }

    // As the backup screen does it: the first share's cipher staged, every other one asked
    // for when the core reaches it. Returns how many were asked for.
    private fun <T> withOnDemandCiphers(
        first: Cipher,
        firstKey: String?,
        role: AndroidKeystoreStorage.CipherRole,
        cipherFor: (String) -> Cipher,
        block: () -> T
    ): Pair<T, Int> {
        var asked = 0
        val result = withCiphers({ id ->
            storage.setPendingCipher(id, first, role, shareKey = firstKey)
            storage.setCipherProvider(id) { key, wanted ->
                if (wanted != role) null else cipherFor(key).also { asked++ }
            }
        }) { block() }
        return result to asked
    }

    private fun backUpOnDemand(): Pair<ByteArray, Int> {
        val groups = storedGroups()
        return withOnDemandCiphers(
            requireNotNull(storage.getCipherForShareDecryption(groups.first())),
            groups.first(),
            AndroidKeystoreStorage.CipherRole.DECRYPT,
            { key -> requireNotNull(storage.getCipherForShareDecryption(key)) }
        ) { mobile.createBackup(PASSPHRASE) }
    }

    @Test
    fun aVaultWithTwoSharesBacksUpAndRestoresBoth() {
        val first = importNewGroup()
        val second = importNewGroup()
        val originals = listOf(first, second).associateWith { loadShare(it) }
        val (backup, askedForBackup) = backUpOnDemand()
        assertEquals("one more cipher, for the second share", 1, askedForBackup)
        mobile.deleteShareByKey(first)
        mobile.deleteShareByKey(second)
        assertTrue(storedGroups().isEmpty())

        val (info, askedForRestore) = withOnDemandCiphers(
            storage.getCipherForEncryption(),
            null,
            AndroidKeystoreStorage.CipherRole.ENCRYPT,
            { storage.getCipherForEncryption() }
        ) { mobile.restoreBackup(backup, PASSPHRASE) }

        assertEquals(2u, info.shareCount)
        assertEquals(1, askedForRestore)
        originals.forEach { (group, original) ->
            assertTrue("$group must be listed", group in storedGroups())
            assertTrue("$group must read back as it was", original.contentEquals(loadShare(group)))
        }
    }

    // More shares than the Keystore keeps operations open for: holding every cipher at
    // once had the oldest pruned and the backup fail, so each is opened only when needed.
    @Test
    fun aVaultWithMoreSharesThanOpenOperationsBacksUp() {
        repeat(MANY_SHARES) { importNewGroup() }
        val (backup, asked) = backUpOnDemand()
        assertEquals(MANY_SHARES - 1, asked)
        assertEquals(MANY_SHARES.toUInt(), mobile.verifyBackup(backup, PASSPHRASE).shareCount)
    }

    // A cancelled prompt ends the request: nothing is handed to the core in its place.
    @Test
    fun aRefusedPromptFailsTheBackup() {
        importNewGroup()
        importNewGroup()
        val groups = storedGroups()
        val result = runCatching {
            withCiphers({ id ->
                storage.setPendingCipher(
                    id,
                    requireNotNull(storage.getCipherForShareDecryption(groups.first())),
                    AndroidKeystoreStorage.CipherRole.DECRYPT,
                    shareKey = groups.first()
                )
                storage.setCipherProvider(id) { _, _ -> null }
            }) { mobile.createBackup(PASSPHRASE) }
        }
        assertTrue(result.isFailure)
    }

    // What the screen staged before: one cipher for the request, which opens one share.
    @Test
    fun oneCipherCannotBackUpTwoShares() {
        importNewGroup()
        importNewGroup()
        assertTrue(runCatching { withCipher(backupCipher()) { mobile.createBackup(PASSPHRASE) } }.isFailure)
    }

    @Test
    fun aCipherStagedForOneShareIsNotSpentOnAnother() {
        val first = importNewGroup()
        val second = importNewGroup()
        val requestId = "restore-cipher-keyed-${System.nanoTime()}"
        storage.setPendingCipher(
            requestId,
            requireNotNull(storage.getCipherForShareDecryption(first)),
            AndroidKeystoreStorage.CipherRole.DECRYPT,
            shareKey = first
        )
        storage.setRequestIdContext(requestId)
        try {
            assertTrue(runCatching { storage.loadShareByKey(second) }.isFailure)
            assertTrue(storage.loadShareByKey(first).isNotEmpty())
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
        }
    }

    private fun loadShare(group: String): ByteArray {
        val cipher = requireNotNull(storage.getCipherForShareDecryption(group))
        return withCipher(cipher) { storage.loadShareByKey(group) }
    }

    // The probe the core makes before it writes a share must not spend the cipher
    // the write needs.
    @Test
    fun aLoadOfAnAbsentShareLeavesTheCipherQueued() {
        val requestId = "restore-cipher-probe-${System.nanoTime()}"
        storage.setPendingCipher(requestId, storage.getCipherForEncryption())
        storage.setRequestIdContext(requestId)
        try {
            assertTrue(runCatching { storage.loadShareByKey(ABSENT_GROUP) }.isFailure)
            assertNotNull("the cipher must still be there", storage.consumePendingCipher(requestId))
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
        }
    }

    private companion object {
        const val SUFFIX = "_restore_cipher_test"
        const val ALIAS = "keep_frost_share$SUFFIX"
        const val SHARE_DATA = "share_data"
        const val ABSENT_GROUP = "00000000000000000000000000000000000000000000000000000000000000ab"
        const val PASSPHRASE = "restore-cipher-test-passphrase"
        const val MANY_SHARES = 20
    }
}
