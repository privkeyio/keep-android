package io.privkey.keep.storage

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.AccountActions
import io.privkey.keep.R
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.ShareInfo
import io.privkey.keep.uniffi.ShareMetadataInfo
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.util.UUID

/**
 * Recovering a pending DKG share through the app's own flow, with the stash planted the way
 * a ceremony leaves it. A share already stored under the stash's group is read rather than
 * written, so the recovery hands the core the share's decrypt cipher, and the active
 * account and live node stay as they were.
 *
 * The stash secret is wrapped under the fixed production DKG alias, so, as in
 * [DkgSecretStashRoundTripTest], the alias is seeded with a twin that needs no biometric,
 * and the test skips on a device that holds a real, auth-gated one.
 */
@RunWith(AndroidJUnit4::class)
class DkgRecoveryOverStoredShareTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private lateinit var storage: AndroidKeystoreStorage
    private lateinit var mobile: KeepMobile
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val created = mutableSetOf<String>()
    private var ownsAlias = false
    private var nodeDrops = 0

    @Before
    fun setup() {
        assumeTrue("refusing to run: a real auth-gated DKG key is present on this device", !productionDkgKeyPresent())
        if (keyStore.containsAlias(DKG_ALIAS)) keyStore.deleteEntry(DKG_ALIAS)
        seedNonAuthTwinAlias()
        ownsAlias = true
        storage = AndroidKeystoreStorage(context, requireUserAuth = false, keystoreAlias = ALIAS, prefsSuffix = SUFFIX)
        mobile = KeepMobile(storage)
    }

    @After
    fun teardown() {
        scope.cancel()
        if (!ownsAlias) return
        runCatching { storage.deleteShareByKey(SECRET_KEY) }
        runCatching { storage.deleteShareByKey(MARKER_KEY) }
        created.forEach { group ->
            runCatching { mobile.deleteShareByKey(group) }
            context.deleteSharedPreferences(storage.sharePrefsNameFor(group))
        }
        context.deleteSharedPreferences(storage.sharePrefsNameFor(MARKER_KEY))
        context.deleteSharedPreferences(MULTI_PREFS)
        mobile.destroy()
        keyStore.aliases().toList().filter { it.startsWith(ALIAS) || it == DKG_ALIAS }.forEach { keyStore.deleteEntry(it) }
    }

    @Test
    fun aShareAlreadyStoredIsReadNotWrittenAndTheActiveAccountStays() {
        val group = mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "dkg-recover-test", PASSPHRASE)
        val other = mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "dkg-recover-other", PASSPHRASE)
        import(group.shares[0].exportData)
        import(other.shares[0].exportData)
        assertEquals(other.groupPubkey, storage.getActiveShareKey())
        stash(group.groupPubkey, group.shares[0].exportData)

        val result = recover()

        assertEquals(group.groupPubkey, (result as Recovered).info?.groupPubkey)
        assertEquals("the active account stays", other.groupPubkey, storage.getActiveShareKey())
        assertEquals("a recovery that wrote nothing does not drop the node", 0, nodeDrops)
        assertNull("the stash is cleared", mobile.pendingDkgShare())
    }

    @Test
    fun anotherShareOfTheStoredGroupIsRefusedWithItsReasonAndTheStashKept() {
        val group = mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "dkg-recover-test", PASSPHRASE)
        import(group.shares[0].exportData)
        stash(group.groupPubkey, group.shares[1].exportData)

        val result = recover()

        assertEquals(Dismissed(context.getString(R.string.account_import_other_share_stored)), result)
        assertNotNull("the stash is kept", mobile.pendingDkgShare())
        assertEquals(0, nodeDrops)
    }

    @Test
    fun aNewGroupIsStoredAndBecomesTheActiveAccount() {
        val other = mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "dkg-recover-other", PASSPHRASE)
        val group = mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "dkg-recover-test", PASSPHRASE)
        import(other.shares[0].exportData)
        stash(group.groupPubkey, group.shares[0].exportData)
        created += group.groupPubkey

        val result = recover()

        assertEquals(group.groupPubkey, (result as Recovered).info?.groupPubkey)
        assertEquals(group.groupPubkey, storage.getActiveShareKey())
        assertEquals("a store that moved the active account drops the node", 1, nodeDrops)
        assertNull(mobile.pendingDkgShare())
    }

    private sealed interface Outcome
    private data class Recovered(val info: ShareInfo?) : Outcome
    private data class Dismissed(val reason: String?) : Outcome

    private fun recover(): Outcome {
        val done = CompletableDeferred<Outcome>()
        val actions = AccountActions(
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
        actions.recoverPendingDkgShare(
            title = "test",
            subtitle = "test",
            onResult = { done.complete(Recovered(it)) },
            onDismiss = { done.complete(Dismissed(it)) },
        )
        return runBlocking { withTimeout(60_000) { done.await() } }
    }

    private fun import(exportData: String) {
        val requestId = "dkg-recover-test-${System.nanoTime()}"
        storage.setPendingCipher(requestId, storage.getCipherForEncryption())
        storage.setRequestIdContext(requestId)
        try {
            created += mobile.importShare(exportData, PASSPHRASE, "dkg-recover-test").groupPubkey
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
        }
    }

    // The two records a vault-protected ceremony leaves for recovery.
    private fun stash(groupPubkey: String, exportData: String) {
        val marker = JSONObject().put("name", "dkg-recover-test").put("group_pubkey_hex", groupPubkey).put("vault_protected", true)
        storage.storeShareByKey(MARKER_KEY, marker.toString().toByteArray(), META)
        val secret = JSONObject().put("share_export", exportData).put("vault_passphrase", PASSPHRASE)
        storage.storeShareByKey(SECRET_KEY, secret.toString().toByteArray(), META)
        assertNotNull("the planted stash reads as pending", mobile.pendingDkgShare())
    }

    private fun productionDkgKeyPresent(): Boolean {
        if (!keyStore.containsAlias(DKG_ALIAS)) return false
        val key = keyStore.getKey(DKG_ALIAS, null) as? PrivateKey ?: return false
        val info = runCatching {
            KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        }.getOrNull() ?: return false
        return info.isUserAuthenticationRequired
    }

    private fun seedNonAuthTwinAlias() {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore").apply {
            initialize(
                KeyGenParameterSpec.Builder(DKG_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(2048)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .build()
            )
        }.generateKeyPair()
    }

    private companion object {
        const val SUFFIX = "_dkg_recover_test"
        const val ALIAS = "keep_frost_share$SUFFIX"
        const val MULTI_PREFS = "keep_multi_share_prefs$SUFFIX"
        const val DKG_ALIAS = "keep_dkg_secret"
        const val MARKER_KEY = "__keep_dkg_pending_v1"
        const val SECRET_KEY = "__keep_dkg_secret_v1"
        const val PASSPHRASE = "dkg-recover-test-passphrase"
        val META = ShareMetadataInfo("dkg_pending", 0u, 0u, 0u, ByteArray(0), false)
    }
}
