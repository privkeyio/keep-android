package io.privkey.keep.storage

import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * The auth-gated StrongBox key cannot be exercised at use time without a biometric,
 * so its use-time capability is validated against a throwaway non-auth probe key. If
 * that probe fails, the auth key must be regenerated on the TEE rather than left on a
 * StrongBox that will later reject the operation. On working StrongBox hardware the
 * probe would always pass, so it is forced to fail here to reach the downgrade path.
 */
@RunWith(AndroidJUnit4::class)
class StrongBoxAuthKeyFallbackTest {

    private val ctx get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val shareKey = "__keep_strongbox_auth_fallback_test"
    private lateinit var keyStore: KeyStore
    private lateinit var alias: String

    @Before fun setup() {
        keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        alias = AndroidKeystoreStorage(ctx, requireUserAuth = true).keystoreAliasFor(shareKey)
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    @After fun teardown() {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    private fun assumeBiometricEnrolled() = assumeTrue(
        "requires an enrolled strong biometric",
        BiometricManager.from(ctx)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS
    )

    private fun securityLevelOf(key: SecretKey): Int {
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return info.securityLevel
    }

    /**
     * With the use-time probe forced to fail, an auth-gated key on a StrongBox device
     * must land on the TEE. Generation succeeding on StrongBox is not enough: a device
     * that rejects the operation only at use time would otherwise keep a key it cannot
     * use, and the auth path never gets to exercise it before storing a real share.
     */
    @Test fun authKeyDowngradesToTeeWhenStrongBoxProbeFails() {
        assumeTrue(ctx.packageManager.hasSystemFeature("android.hardware.strongbox_keystore"))
        assumeBiometricEnrolled()

        val storage = AndroidKeystoreStorage(ctx, requireUserAuth = true, strongBoxUseTimeProbe = { false })
        val key = storage.ensureShareKey(shareKey)

        assertNotEquals(
            "a failing StrongBox probe must downgrade the auth key off StrongBox",
            KeyProperties.SECURITY_LEVEL_STRONGBOX,
            securityLevelOf(key)
        )
        assertEquals(
            "the downgraded auth key should be TEE-backed",
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
            securityLevelOf(key)
        )
    }
}
