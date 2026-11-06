package io.privkey.keep.storage

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.AccountActions
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.QuarantineDiscard
import io.privkey.keep.uniffi.ShareProbe
import io.privkey.keep.uniffi.ShareRegistryRead
import io.privkey.keep.uniffi.ShareStoreStatus
import io.privkey.keep.uniffi.UnreadableShareRemoval
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import android.system.Os
import android.util.Base64
import javax.crypto.Cipher

@RunWith(AndroidJUnit4::class)
class UnreadableShareRemovalTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private lateinit var storage: AndroidKeystoreStorage
    private lateinit var mobile: KeepMobile
    private val created = mutableSetOf<String>()
    private var nodeDrops = 0

    @Before
    fun setup() {
        storage = AndroidKeystoreStorage(context, requireUserAuth = false, keystoreAlias = ALIAS, prefsSuffix = SUFFIX)
        mobile = KeepMobile(storage)
    }

    @After
    fun teardown() {
        scope.cancel()
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        created.forEach { group ->
            runCatching { mobile.deleteShareByKey(group) }
            storage.shareKeyAliases(group).forEach { keyStore.deleteEntry(it) }
            context.deleteSharedPreferences(storage.sharePrefsNameFor(group))
        }
        context.deleteSharedPreferences(MULTI_PREFS)
        keyStore.aliases().toList().filter { it.startsWith(ALIAS) }.forEach { keyStore.deleteEntry(it) }
    }

    private fun <T> withCipher(cipher: Cipher, block: () -> T): T {
        val requestId = "unreadable-removal-test-${System.nanoTime()}"
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
        val info = withCipher(storage.getCipherForEncryption()) { mobile.importShare(export, PASSPHRASE, "removal-test") }
        created += info.groupPubkey
        return info.groupPubkey
    }

    private fun share(): String =
        mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "removal-test", PASSPHRASE).shares.first().exportData

    private fun breakShare(group: String) {
        val prefsName = storage.sharePrefsNameFor(group)
        val raw = rawPrefs(context, prefsName)
        val before = raw.all.keys.toSet()
        KeystoreEncryptedPrefs.create(context, prefsName).edit().remove(GROUP_PUBKEY).commit()
        val groupName = (before - raw.all.keys.toSet()).single()
        raw.edit().putString(groupName, "not-a-stored-value").commit()
    }

    private fun actions() = AccountActions(
        keepMobile = mobile,
        storage = storage,
        coroutineScope = scope,
        appContext = context,
        onBiometricRequest = { _, _, cipher, onResult -> onResult(cipher) },
        onAccountSwitched = { true },
        onAccountDeleted = {},
        onLiveNodeDropped = { nodeDrops++ },
        onStateChanged = {},
        markBunkerRevokeAhead = { { _ -> } },
    )

    private fun <T> await(start: ((T) -> Unit) -> Unit): T {
        val done = CompletableDeferred<T>()
        start { done.complete(it) }
        return runBlocking { withTimeout(60_000) { done.await() } }
    }

    private fun remove(group: String): UnreadableShareRemoval? =
        await { actions().removeUnreadableShare(group, null, it) }

    private fun restore(group: String): Boolean = await { actions().restoreQuarantinedShare(group, it) }

    private fun discard(group: String): QuarantineDiscard? = await { actions().discardLostShare(group, null, it) }

    private fun loseKeys(group: String) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        storage.shareKeyAliases(group).forEach { keyStore.deleteEntry(it) }
    }

    private fun registered(): Int = (storage.readShareRegistry() as ShareRegistryRead.Readable).shares.size

    @Test
    fun aShareWhoseKeysAreGoneIsSetAsideRestoredAndDiscarded() {
        val export = share()
        val group = import(export)
        breakShare(group)
        loseKeys(group)
        assertEquals(ShareStoreStatus.SomeUnreadable(listOf(group)), mobile.shareStoreStatus())
        assertEquals(ShareProbe.Lost, storage.probeShareByKey(group))

        assertTrue(remove(group) is UnreadableShareRemoval.Removed)
        assertEquals(1, nodeDrops)
        assertEquals(ShareStoreStatus.Readable, mobile.shareStoreStatus())
        assertEquals(listOf(group), mobile.listQuarantinedShares())
        assertEquals(0, registered())
        assertTrue("a set-aside share is not written over", runCatching { import(export) }.isFailure)
        assertEquals(listOf(group), mobile.listQuarantinedShares())

        assertTrue(restore(group))
        assertEquals(emptyList<String>(), mobile.listQuarantinedShares())
        assertEquals(ShareStoreStatus.SomeUnreadable(listOf(group)), mobile.shareStoreStatus())

        assertTrue(remove(group) is UnreadableShareRemoval.Removed)
        assertTrue(discard(group) is QuarantineDiscard.Discarded)
        assertEquals("each set-aside and the discard drop the live node", 3, nodeDrops)
        assertEquals(emptyList<String>(), mobile.listQuarantinedShares())
        assertEquals(ShareStoreStatus.Readable, mobile.shareStoreStatus())
        assertEquals(group, import(export))
        assertEquals(1, registered())
    }

    @Test
    fun aShareWhoseCiphertextFailsItsTagIsSetAside() {
        val group = import(share())
        val prefs = KeystoreEncryptedPrefs.create(context, storage.sharePrefsNameFor(group))
        assertTrue(prefs.edit().putString(SHARE_DATA, Base64.encodeToString(ByteArray(64) { 7 }, Base64.NO_WRAP)).commit())
        breakShare(group)
        assertEquals(ShareProbe.Lost, storage.probeShareByKey(group))

        assertTrue(remove(group) is UnreadableShareRemoval.Removed)
        assertEquals(listOf(group), mobile.listQuarantinedShares())
    }

    @Test
    fun aListedUnreadableShareWhoseSecretLoadsIsKept() {
        val group = import(share())
        breakShare(group)
        assertEquals(ShareStoreStatus.SomeUnreadable(listOf(group)), mobile.shareStoreStatus())
        assertTrue(storage.probeShareByKey(group) is ShareProbe.Loads)

        assertEquals(UnreadableShareRemoval.Recoverable, remove(group))
        assertEquals(ShareStoreStatus.SomeUnreadable(listOf(group)), mobile.shareStoreStatus())
        assertEquals(0, nodeDrops)
        assertEquals(emptyList<String>(), mobile.listQuarantinedShares())
    }

    @Test
    fun aShareThatReadsIsNotSetAside() {
        val group = import(share())

        assertEquals(UnreadableShareRemoval.Readable, remove(group))

        assertEquals(1, registered())
        assertEquals(0, nodeDrops)
        assertEquals(ShareStoreStatus.Readable, mobile.shareStoreStatus())
    }

    // The share file's own key no longer loads, so its ciphertext cannot be read and
    // whether the secret is lost cannot be told. It stays listed.
    @Test
    fun aShareWhoseFileWillNotOpenIsKeptUnverified() {
        val group = import(share())
        val fileKey = "keep_prefs_${storage.sharePrefsNameFor(group)}"
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(fileKey)
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(KeyGenParameterSpec.Builder(fileKey, KeyProperties.PURPOSE_SIGN).setDigests(KeyProperties.DIGEST_SHA256).build())
        }.generateKeyPair()
        assertEquals(ShareStoreStatus.SomeUnreadable(listOf(group)), mobile.shareStoreStatus())

        assertEquals(UnreadableShareRemoval.Unverified, remove(group))
        assertEquals(ShareStoreStatus.SomeUnreadable(listOf(group)), mobile.shareStoreStatus())
        assertEquals(emptyList<String>(), mobile.listQuarantinedShares())
    }

    @Test
    fun aSetAsideShareThatLoadsIsNotDiscarded() {
        val group = import(share())
        storage.quarantineShareByKey(group)
        assertEquals(listOf(group), mobile.listQuarantinedShares())

        assertEquals(QuarantineDiscard.Readable, discard(group))
        assertEquals(0, nodeDrops)
        assertEquals(listOf(group), mobile.listQuarantinedShares())
        assertTrue(storage.probeShareByKey(group) is ShareProbe.Loads)

        assertTrue(restore(group))
        assertEquals(1, registered())
        assertEquals(ShareStoreStatus.Readable, mobile.shareStoreStatus())
    }

    // Whether a set-aside share whose file will not open is lost cannot be told, so the
    // discard keeps it, leaves the node alone and reports that.
    @Test
    fun aSetAsideShareThatCannotBeCheckedIsNotDiscarded() {
        val group = import(share())
        val fileKey = "keep_prefs_${storage.sharePrefsNameFor(group)}"
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(fileKey)
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(KeyGenParameterSpec.Builder(fileKey, KeyProperties.PURPOSE_SIGN).setDigests(KeyProperties.DIGEST_SHA256).build())
        }.generateKeyPair()
        storage.quarantineShareByKey(group)

        assertEquals(QuarantineDiscard.Unverified, discard(group))
        assertEquals(0, nodeDrops)
        assertEquals(listOf(group), mobile.listQuarantinedShares())
    }

    private fun setAsideWithEmptiedRecord(): String {
        val group = import(share())
        storage.quarantineShareByKey(group)
        assertTrue(rawPrefs(context, storage.sharePrefsNameFor(group)).edit().clear().commit())
        return group
    }

    private fun recordFile(group: String) = File(context.dataDir, "shared_prefs/${storage.sharePrefsNameFor(group)}.xml")

    private fun assertKeptUnverified(group: String) {
        assertEquals(ShareProbe.Unknown, storage.probeShareByKey(group))
        assertEquals(QuarantineDiscard.Unverified, discard(group))
        assertEquals(0, nodeDrops)
        assertTrue(group in mobile.listQuarantinedShares())
    }

    // A discard that emptied the record but failed before deregistering it leaves the
    // share's key behind with nothing to open. A retry finishes the discard.
    @Test
    fun aSetAsideShareWhoseRecordWasEmptiedIsDiscarded() {
        val group = setAsideWithEmptiedRecord()
        assertEquals(ShareProbe.Lost, storage.probeShareByKey(group))

        assertTrue(discard(group) is QuarantineDiscard.Discarded)
        assertEquals(1, nodeDrops)
        assertEquals(emptyList<String>(), mobile.listQuarantinedShares())
        assertEquals(0, registered())
    }

    // An empty file is what a write leaves only with its backup beside it, and without
    // one it holds nothing.
    @Test
    fun aSetAsideShareWhoseRecordFileIsEmptyIsDiscarded() {
        val group = setAsideWithEmptiedRecord()
        recordFile(group).writeText("")
        assertEquals(ShareProbe.Lost, storage.probeShareByKey(group))

        assertTrue(discard(group) is QuarantineDiscard.Discarded)
        assertEquals(emptyList<String>(), mobile.listQuarantinedShares())
    }

    @Test
    fun aSetAsideShareWhoseRecordFileIsGoneIsDiscarded() {
        val group = import(share())
        storage.quarantineShareByKey(group)
        assertTrue(context.deleteSharedPreferences(storage.sharePrefsNameFor(group)))
        assertEquals(ShareProbe.Lost, storage.probeShareByKey(group))

        assertTrue(discard(group) is QuarantineDiscard.Discarded)
        assertEquals(emptyList<String>(), mobile.listQuarantinedShares())
    }

    // The disk check reads a path it builds itself. Where SharedPreferences still holds
    // the record, as it would if that path were wrong, the share is not called empty.
    @Test
    fun aRecordSharedPreferencesStillHoldsIsNotCalledEmpty() {
        val group = import(share())
        storage.quarantineShareByKey(group)
        assertTrue(recordFile(group).delete())

        assertTrue(storage.probeShareByKey(group) is ShareProbe.Loads)
        assertEquals(QuarantineDiscard.Readable, discard(group))
        assertEquals(listOf(group), mobile.listQuarantinedShares())
    }

    // A failure to look reads as a missing file through File.exists, which must not count.
    @Test
    fun aRecordThatCannotBeLookedForIsNotCalledEmpty() {
        val group = setAsideWithEmptiedRecord()
        assertTrue(recordFile(group).delete())
        val dir = recordFile(group).parentFile!!.path
        val mode = Os.stat(dir).st_mode and 0x1ff
        Os.chmod(dir, mode and 0x49.inv())
        try {
            assertEquals(ShareProbe.Unknown, storage.probeShareByKey(group))
        } finally {
            Os.chmod(dir, mode)
        }
    }

    @Test
    fun aSetAsideShareWithOnlyItsIvLeftIsNotDiscarded() {
        val group = import(share())
        storage.quarantineShareByKey(group)
        assertTrue(KeystoreEncryptedPrefs.create(context, storage.sharePrefsNameFor(group)).edit().remove(SHARE_DATA).commit())

        assertKeptUnverified(group)
    }

    // SharedPreferences reads a file it cannot parse as empty, so the probe has to read
    // the file itself before calling the record gone.
    @Test
    fun aSetAsideShareWhoseRecordFileWillNotParseIsNotDiscarded() {
        val unloadables = listOf(
            "<map><string name=",
            "<record><string name=\"k\">v</string></record>",
            "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>",
        )
        for (unloadable in unloadables) {
            val group = setAsideWithEmptiedRecord()
            recordFile(group).writeText(unloadable)

            // The discard asks for the share's cipher first, which opens the file.
            storage.cipherForShareProbe(group)
            assertKeptUnverified(group)
            assertEquals(unloadable, recordFile(group).readText())
        }
    }

    // A backup is the write SharedPreferences restores when it next loads the file, so
    // the empty file beside it says nothing about the record.
    @Test
    fun aRecordWithAPendingBackupIsNotCalledEmpty() {
        val group = setAsideWithEmptiedRecord()
        val backup = File(recordFile(group).path + ".bak")
        backup.writeText("<map><string name=\"k\">v</string></map>")

        try {
            assertEquals(ShareProbe.Unknown, storage.probeShareByKey(group))
        } finally {
            backup.delete()
        }
    }

    @Test
    fun discardingAShareThatIsNotSetAsideChangesNothing() {
        val group = import(share())

        assertEquals(QuarantineDiscard.NotSetAside, discard(group))
        assertEquals(1, registered())
        assertEquals(0, nodeDrops)
    }

    @Test
    fun theProbeAnswersUnknownForKeysThatAreNotShares() {
        assertEquals(ShareProbe.Unknown, storage.probeShareByKey(""))
    }

    private companion object {
        const val SUFFIX = "_unreadable_removal_test"
        const val ALIAS = "keep_frost_share$SUFFIX"
        const val MULTI_PREFS = "keep_multi_share_prefs$SUFFIX"
        const val GROUP_PUBKEY = "share_group_pubkey"
        const val SHARE_DATA = "share_data"
        const val PASSPHRASE = "unreadable-removal-test-passphrase"
    }
}
