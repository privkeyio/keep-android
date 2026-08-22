package io.privkey.keep.nip55

import android.security.keystore.KeyInfo
import androidx.biometric.BiometricManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import org.junit.Assert.*
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FrostSigningIntegrationTest {

    private var app: KeepMobileApp? = null
    private var handler: Nip55Handler? = null
    private var testStorage: AndroidKeystoreStorage? = null
    private var testMobile: KeepMobile? = null
    private var testNip55Handler: Nip55Handler? = null

    private companion object {
        // Matches AndroidKeystoreStorage.KEYSTORE_ALIAS (the legacy single-share AES key).
        const val SHARE_KEY_ALIAS = "keep_frost_share"
    }

    private fun hasBiometricEnrollment(): Boolean {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val result = BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        return result == BiometricManager.BIOMETRIC_SUCCESS
    }

    @Before
    fun setup() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        app = context.applicationContext as? KeepMobileApp

        // Always use no-auth storage for instrumented runs. The app's storage is
        // auth-per-use (setUserAuthenticationParameters(0, ...)) whenever a device
        // has a biometric enrolled, and doFinal cannot succeed unattended.
        val storage = AndroidKeystoreStorage(context, requireUserAuth = false)
        // requireUserAuth is only honored when the key is created; an existing
        // keep_frost_share alias is reused as-is. A prior run on a biometric
        // device could leave it auth-gated, which would make importShare's doFinal
        // require a biometric. Drop leftover auth-gated key material so a fresh
        // non-auth key is generated; if a real share sits behind it, skip instead.
        resetIfShareKeyRequiresAuth(storage)
        val mobile = KeepMobile(storage)
        testStorage = storage
        testMobile = mobile
        testNip55Handler = Nip55Handler(mobile)
        ensureShareExistsNoAuth(mobile, storage)
    }

    private fun resetIfShareKeyRequiresAuth(storage: AndroidKeystoreStorage) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!keyStore.containsAlias(SHARE_KEY_ALIAS)) return
        val authRequired = runCatching {
            val key = keyStore.getKey(SHARE_KEY_ALIAS, null) as? SecretKey ?: return
            val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            (factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo).isUserAuthenticationRequired
        }.getOrDefault(false)
        if (!authRequired) return
        // An auth-gated alias with a share stored behind it is a real user share:
        // production always creates this alias with requireUserAuth = true, while this
        // test only ever writes no-auth fixture shares, so an auth-gated share is never
        // one of ours. deleteShare() would drop both the share and the key that decrypts
        // it, so skip instead of destroying user data.
        assumeFalse(
            "device holds a real auth-gated share; skipping to avoid destroying it",
            storage.hasShare()
        )
        // Auth-gated key with no share behind it is leftover key material from an
        // earlier aborted run; dropping it lets a fresh no-auth key be generated.
        storage.deleteShare()
    }

    private fun getKeepMobile(): KeepMobile? = testMobile ?: app?.getKeepMobile()
    private fun getStorage(): AndroidKeystoreStorage? = testStorage ?: app?.getStorage()
    private fun getNip55Handler(): Nip55Handler? = testNip55Handler ?: app?.getNip55Handler()

    private fun ensureShareExistsNoAuth(mobile: KeepMobile, storage: AndroidKeystoreStorage) {
        if (storage.hasShare()) {
            val metadata = storage.getShareMetadata()
            if (metadata != null && metadata.threshold == 2u.toUShort() && metadata.totalShares == 2u.toUShort()) return
        }

        val result = mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "test", "test")
        val exportData = result.shares.first().exportData
        val requestId = "test-setup-noauth"
        val cipher = storage.getCipherForEncryption()
        storage.setRequestIdContext(requestId)
        storage.setPendingCipher(requestId, cipher)
        try {
            mobile.importShare(exportData, "test", "test")
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
        }
    }

    @Test
    fun appInitialized_keepMobileExists() {
        assertNotNull("KeepMobileApp should be available", app)
        assertNotNull("KeepMobile instance should exist", getKeepMobile())
        assertNull("No init error expected", app!!.getInitError())
    }

    @Test
    fun nip55Handler_isAvailable() {
        assertNotNull("Nip55Handler should be initialized", getNip55Handler())
    }

    @Test
    fun storage_hasShareLoaded() {
        val storage = getStorage()
        assertNotNull("Storage should be available", storage)
        assertTrue("Share should be stored after import", storage!!.hasShare())
    }

    @Test
    fun shareMetadata_isValid() {
        val storage = getStorage()
        val metadata = storage?.getShareMetadata()
        assertNotNull("Share metadata should be readable", metadata)

        assertTrue("Identifier should be positive", metadata!!.identifier > 0u.toUShort())
        assertTrue("Threshold should be >= 2", metadata.threshold >= 2u.toUShort())
        assertTrue("Total shares should be >= threshold", metadata.totalShares >= metadata.threshold)
        assertTrue("Group pubkey should not be empty", metadata.groupPubkey.isNotEmpty())
    }

    @Test
    fun shareMetadata_hasExpectedThresholdAndTotal() {
        val storage = getStorage()
        val metadata = storage?.getShareMetadata()
        assertNotNull("Share metadata should be present", metadata)

        assertEquals(
            "FROST threshold should be 2",
            2u.toUShort(),
            metadata!!.threshold
        )
        assertEquals(
            "FROST totalShares should be 2",
            2u.toUShort(),
            metadata.totalShares
        )
    }

    @Test
    fun shareMetadata_groupPubkey_is32Bytes() {
        val storage = getStorage()
        val metadata = storage?.getShareMetadata()
        assertNotNull(metadata)
        assertEquals(
            "Group pubkey should be 32 bytes (secp256k1 x-only)",
            32,
            metadata!!.groupPubkey.size
        )
    }

    @Test
    fun shareMetadata_groupPubkey_asHex_is64Chars() {
        val storage = getStorage()
        val metadata = storage?.getShareMetadata()
        assertNotNull(metadata)
        val hex = metadata!!.groupPubkey.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        assertEquals("Hex pubkey should be 64 chars", 64, hex.length)
        assertTrue("Hex pubkey should only contain hex chars", hex.matches(Regex("[0-9a-f]+")))
    }

    @Test
    fun nip55Handler_getPublicKey_returnsValidPubkey() {
        val handler = requireNotNull(getNip55Handler()) { "Nip55Handler must not be null" }
        val mobile = requireNotNull(getKeepMobile()) { "KeepMobile must not be null" }
        val shareInfo = requireNotNull(mobile.getShareInfo()) { "ShareInfo must not be null" }

        val request = Nip55Request(
            requestType = Nip55RequestType.GET_PUBLIC_KEY,
            content = "",
            pubkey = null,
            returnType = "signature",
            compressionType = "none",
            callbackUrl = null,
            id = "test-frost-pubkey",
            currentUser = null,
            permissions = null,
            kind = null,
            scope = null
        )

        val response = handler.handleRequest(request, "io.privkey.keep.test")
        assertNotNull("Response should not be null", response)
        assertTrue("Result should be 64-char hex pubkey", response.result.length == 64)
        assertTrue("Result should match share info pubkey", response.result == shareInfo.groupPubkey)
        assertNull("Error should be null", response.error)
    }

    @Test
    fun nip55Handler_getPublicKey_matchesStoredMetadata() {
        val handler = requireNotNull(getNip55Handler()) { "Nip55Handler must not be null" }
        val storage = requireNotNull(getStorage()) { "Storage must not be null" }
        val metadata = requireNotNull(storage.getShareMetadata()) { "ShareMetadata must not be null" }

        val request = Nip55Request(
            requestType = Nip55RequestType.GET_PUBLIC_KEY,
            content = "",
            pubkey = null,
            returnType = "signature",
            compressionType = "none",
            callbackUrl = null,
            id = "test-frost-pubkey-match",
            currentUser = null,
            permissions = null,
            kind = null,
            scope = null
        )

        val response = handler.handleRequest(request, "io.privkey.keep.test")
        val storedPubkey = metadata.groupPubkey.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        assertEquals(
            "Handler pubkey should match stored metadata pubkey",
            storedPubkey,
            response.result
        )
    }

    @Test
    fun permissionStore_isAvailable() {
        assertNotNull("PermissionStore should be initialized", app!!.getPermissionStore())
    }

    @Test
    fun callerVerificationStore_isAvailable() {
        assertNotNull("CallerVerificationStore should be initialized", app!!.getCallerVerificationStore())
    }

    @Test
    fun killSwitch_isDisabledByDefault() {
        val mobile = getKeepMobile()
        assertNotNull(mobile)
        assertFalse("Kill switch should be disabled by default", mobile!!.getKillSwitch())
    }

    @Test
    fun securityLevel_isNotNone() {
        val storage = getStorage()
        assertNotNull(storage)
        val level = storage!!.getSecurityLevel()
        assertNotEquals("Security level should not be 'none'", "none", level)
        if (hasBiometricEnrollment()) {
            assertTrue(
                "Security level should be tee or strongbox",
                level == "tee" || level == "strongbox"
            )
        }
    }
}
