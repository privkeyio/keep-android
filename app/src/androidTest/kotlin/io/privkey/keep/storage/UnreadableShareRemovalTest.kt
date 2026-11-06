package io.privkey.keep.storage

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.AccountActions
import io.privkey.keep.ShareRemoval
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.ShareRegistryRead
import io.privkey.keep.uniffi.ShareStoreStatus
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
import java.security.KeyPairGenerator
import java.security.KeyStore
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
        created.forEach { group ->
            runCatching { mobile.deleteShareByKey(group) }
            context.deleteSharedPreferences(storage.sharePrefsNameFor(group))
        }
        context.deleteSharedPreferences(MULTI_PREFS)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
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

    private fun remove(group: String): ShareRemoval {
        val done = CompletableDeferred<ShareRemoval>()
        AccountActions(
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
        ).removeUnreadableShare(group) { done.complete(it) }
        return runBlocking { withTimeout(60_000) { done.await() } }
    }

    @Test
    fun anUnreadableShareIsRemovedAndItsGroupCanBeImportedAgain() {
        val export = share()
        val group = import(export)
        breakShare(group)
        assertEquals(ShareStoreStatus.SomeUnreadable(listOf(group)), mobile.shareStoreStatus())
        assertTrue("the core refuses to write over it while it is stored", runCatching { import(export) }.isFailure)

        assertEquals(ShareRemoval.REMOVED, remove(group))

        assertEquals(ShareStoreStatus.Readable, mobile.shareStoreStatus())
        assertEquals(1, nodeDrops)
        assertEquals(group, import(export))
        val read = storage.readShareRegistry() as ShareRegistryRead.Readable
        assertEquals(1, read.shares.size)
    }

    @Test
    fun aShareThatReadsIsNotRemoved() {
        val group = import(share())

        assertEquals(ShareRemoval.NO_LONGER_UNREADABLE, remove(group))

        val read = storage.readShareRegistry() as ShareRegistryRead.Readable
        assertEquals(1, read.shares.size)
        assertEquals(0, nodeDrops)
        assertEquals(ShareStoreStatus.Readable, mobile.shareStoreStatus())
    }

    // The share file's own key no longer loads, so the file cannot be opened at all. The
    // delete has removed the share's Keystore aliases by the time it reaches the file, so
    // it has to empty it without opening it, or the share could never be removed.
    @Test
    fun aShareWhoseFileKeyWillNotLoadIsStillRemoved() {
        val export = share()
        val group = import(export)
        val prefsName = storage.sharePrefsNameFor(group)
        val fileKey = "keep_prefs_$prefsName"
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(fileKey)
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(KeyGenParameterSpec.Builder(fileKey, KeyProperties.PURPOSE_SIGN).setDigests(KeyProperties.DIGEST_SHA256).build())
        }.generateKeyPair()
        assertEquals(ShareStoreStatus.SomeUnreadable(listOf(group)), mobile.shareStoreStatus())

        assertEquals(ShareRemoval.REMOVED, remove(group))

        assertEquals(ShareStoreStatus.Readable, mobile.shareStoreStatus())
        assertTrue(rawPrefs(context, prefsName).all.isEmpty())
        assertEquals(group, import(export))
    }

    private companion object {
        const val SUFFIX = "_unreadable_removal_test"
        const val ALIAS = "keep_frost_share$SUFFIX"
        const val MULTI_PREFS = "keep_multi_share_prefs$SUFFIX"
        const val GROUP_PUBKEY = "share_group_pubkey"
        const val PASSPHRASE = "unreadable-removal-test-passphrase"
    }
}
