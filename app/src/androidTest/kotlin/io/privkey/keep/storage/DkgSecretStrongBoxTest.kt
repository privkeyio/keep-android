package io.privkey.keep.storage

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.uniffi.ShareMetadataInfo
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import android.security.keystore.KeyGenParameterSpec
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * The StrongBox fallback only wraps key *generation*. A device can generate a
 * StrongBox key happily and then fail at use time on an unsupported padding or
 * MGF1 digest, and nothing falls back at that point. So it is not enough to see
 * generation succeed: this pins which security level the key actually landed on,
 * so a silent downgrade to TEE on a StrongBox device shows up as a failure rather
 * than passing quietly.
 */
@RunWith(AndroidJUnit4::class)
class DkgSecretStrongBoxTest {

    private val ctx get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val alias = "keep_dkg_secret"
    private lateinit var keyStore: KeyStore

    @Before fun setup() {
        keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    @After fun teardown() {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    private fun securityLevel(): Int {
        val key = keyStore.getKey(alias, null) as PrivateKey
        val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java)
        return info.securityLevel
    }

    /**
     * The DKG alias is created with `AUTH_BIOMETRIC_STRONG` for every use, which the
     * Keystore refuses to generate at all when nothing is enrolled. That is a property
     * of the environment rather than of the change under test, so cases needing the real
     * alias skip instead of failing on a device without biometrics, such as CI's emulator.
     */
    private fun assumeBiometricEnrolled() = assumeTrue(
        "requires an enrolled strong biometric",
        BiometricManager.from(ctx)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS
    )

    /** Writing the DKG secret is what triggers keypair creation. */
    private fun triggerCreation() {
        AndroidKeystoreStorage(ctx, requireUserAuth = false).storeShareByKey(
            "__keep_dkg_secret_v1",
            ByteArray(64) { it.toByte() },
            ShareMetadataInfo("dkg_pending", 0u, 0u, 0u, ByteArray(0), false)
        )
    }

    @Test fun keypairIsCreatedAndUsableForTheWritePath() {
        assumeBiometricEnrolled()
        triggerCreation()
        assertTrue("DKG secret alias should exist after a write", keyStore.containsAlias(alias))
    }

    /**
     * On a device advertising StrongBox the key must actually be StrongBox-backed.
     * If this fails while the feature is present, the fallback fired and the stated
     * hardware guarantee is not the one being delivered.
     */
    /**
     * The decrypt path is where a StrongBox key can still fail after generating
     * cleanly: the alias is created with SHA-256 + OAEP, but the cipher is used
     * with an MGF1-SHA1 mask, and StrongBox authorizes a narrower parameter set
     * than the TEE. `Cipher.init` is where unsupported parameters surface; the
     * auth requirement defers only the `doFinal`, so this reaches the parameter
     * check without needing a biometric.
     */
    @Test fun strongBoxKeyAcceptsTheOaepParametersUsedForDecryption() {
        assumeBiometricEnrolled()
        triggerCreation()
        val storage = AndroidKeystoreStorage(ctx, requireUserAuth = false)
        val cipher = storage.getDkgSecretDecryptCipher()
        assertTrue(
            "StrongBox must accept the OAEP/MGF1 parameters the read path uses",
            cipher != null
        )
    }

    /**
     * Whether StrongBox can actually perform the private-key operation, not just
     * accept its parameters at init. The production alias is auth-bound, so its
     * `doFinal` cannot run unattended; this builds a key with identical StrongBox
     * parameters minus the auth requirement and round-trips through it. That
     * isolates the crypto capability from the auth binding, which the biometric
     * prompts exercise separately.
     */
    @Test fun strongBoxCanActuallyPerformTheOaepPrivateKeyOperation() {
        assumeTrue(ctx.packageManager.hasSystemFeature("android.hardware.strongbox_keystore"))
        val probe = "keep_dkg_strongbox_probe"
        if (keyStore.containsAlias(probe)) keyStore.deleteEntry(probe)
        try {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore").apply {
                initialize(
                    KeyGenParameterSpec.Builder(
                        probe,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    )
                        .setKeySize(2048)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .setIsStrongBoxBacked(true)
                        .build()
                )
            }.generateKeyPair()

            val spec = OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT
            )
            val plaintext = ByteArray(32) { (it * 11).toByte() }

            val enc = Cipher.getInstance("RSA/ECB/OAEPPadding")
            enc.init(Cipher.ENCRYPT_MODE, keyStore.getCertificate(probe).publicKey, spec)
            val ct = enc.doFinal(plaintext)

            val dec = Cipher.getInstance("RSA/ECB/OAEPPadding")
            dec.init(Cipher.DECRYPT_MODE, keyStore.getKey(probe, null) as PrivateKey, spec)
            assertTrue(
                "StrongBox RSA-OAEP decrypt must round-trip the exact plaintext",
                dec.doFinal(ct).contentEquals(plaintext)
            )
        } finally {
            if (keyStore.containsAlias(probe)) keyStore.deleteEntry(probe)
        }
    }

    @Test fun keyIsStrongBoxBackedWhenTheDeviceAdvertisesIt() {
        assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        assumeTrue(ctx.packageManager.hasSystemFeature("android.hardware.strongbox_keystore"))
        assumeBiometricEnrolled()
        triggerCreation()
        assertEquals(
            "device advertises StrongBox, so the DKG keypair must be StrongBox-backed",
            KeyProperties.SECURITY_LEVEL_STRONGBOX,
            securityLevel()
        )
    }
}
