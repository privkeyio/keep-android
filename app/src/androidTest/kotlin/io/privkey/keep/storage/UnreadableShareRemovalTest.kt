package io.privkey.keep.storage

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.AccountActions
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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
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

    private fun remove(group: String): Boolean {
        val done = CompletableDeferred<Boolean>()
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

        assertTrue(remove(group))

        assertEquals(ShareStoreStatus.Readable, mobile.shareStoreStatus())
        assertEquals(1, nodeDrops)
        assertEquals(group, import(export))
        val read = storage.readShareRegistry() as ShareRegistryRead.Readable
        assertEquals(1, read.shares.size)
    }

    @Test
    fun aShareThatReadsIsNotRemoved() {
        val group = import(share())

        assertFalse(remove(group))

        val read = storage.readShareRegistry() as ShareRegistryRead.Readable
        assertEquals(1, read.shares.size)
        assertEquals(0, nodeDrops)
        assertEquals(ShareStoreStatus.Readable, mobile.shareStoreStatus())
    }

    private companion object {
        const val SUFFIX = "_unreadable_removal_test"
        const val ALIAS = "keep_frost_share$SUFFIX"
        const val MULTI_PREFS = "keep_multi_share_prefs$SUFFIX"
        const val GROUP_PUBKEY = "share_group_pubkey"
        const val PASSPHRASE = "unreadable-removal-test-passphrase"
    }
}
