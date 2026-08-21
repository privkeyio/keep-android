package io.privkey.keep.storage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.uniffi.ShareMetadataInfo
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import java.util.UUID

/**
 * The pending-DKG recovery path is gated on a biometric-bound RSA unwrap and, for
 * the full ceremony import, on Rust-side pending-share state that only a real DKG
 * run produces — so the end-to-end recover is hardware-assisted manual verification,
 * not a headless test (see PR #492 / GH #497).
 *
 * What IS reachable without a biometric is the storage-layer crypto that stash
 * recovery actually depends on: `storeDkgSecret` hybrid-wraps the secret under the
 * DKG RSA public key with no auth, and `loadDkgSecret` unwraps it with an authorized
 * private-key cipher. This drives BOTH real halves against a genuine stash, so a
 * regression in the wrap/unwrap contract (OAEP parameters, AES-GCM framing, prefs
 * layout) fails here rather than only surfacing on-device behind a biometric prompt.
 *
 * The only substitution is the auth binding: the production alias is created with
 * `AUTH_BIOMETRIC_STRONG`, whose private-key `doFinal` cannot run unattended, so this
 * seeds the fixed alias with a crypto-identical key minus the auth requirement — the
 * same isolation technique [DkgSecretStrongBoxTest] uses to reach `doFinal` headless.
 * `getOrCreateDkgSecretKeypair` early-returns when the alias already exists, so the
 * real write path wraps under this key exactly as it would the production one.
 */
@RunWith(AndroidJUnit4::class)
class DkgSecretStashRoundTripTest {

    private val ctx get() = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var keyStore: KeyStore
    private lateinit var storage: AndroidKeystoreStorage

    @Before fun setup() {
        keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS)
        storage = AndroidKeystoreStorage(ctx, requireUserAuth = false)
        // Wipe any stash the real alias/prefs may still hold from a prior run.
        runCatching { storage.deleteShareByKey(SECRET_KEY) }
        seedNonAuthTwinAlias()
    }

    @After fun teardown() {
        runCatching { storage.deleteShareByKey(SECRET_KEY) }
        if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS)
    }

    /**
     * Same key shape as `getOrCreateDkgSecretKeypair` (RSA-2048, SHA-256, OAEP) but
     * without `setUserAuthenticationRequired`, so its private-key `doFinal` runs
     * without a prompt. TEE-only and no `setInvalidatedByBiometricEnrollment`, which
     * both require an enrolled biometric the CI emulator lacks.
     */
    private fun seedNonAuthTwinAlias() {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore").apply {
            initialize(
                KeyGenParameterSpec.Builder(
                    ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setKeySize(2048)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .build()
            )
        }.generateKeyPair()
    }

    private fun oaepSpec() =
        OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

    private fun decryptCipher(): Cipher =
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding").apply {
            init(Cipher.DECRYPT_MODE, keyStore.getKey(ALIAS, null) as PrivateKey, oaepSpec())
        }

    private fun writeStash(secret: ByteArray) =
        storage.storeShareByKey(SECRET_KEY, secret, META)

    /** Read is auth-gated: queue an authorized decrypt cipher, then read under its request. */
    private fun readStash(): ByteArray {
        val requestId = UUID.randomUUID().toString()
        storage.setPendingCipher(requestId, decryptCipher(), AndroidKeystoreStorage.CipherRole.DECRYPT)
        storage.setRequestIdContext(requestId)
        return try {
            storage.loadShareByKey(SECRET_KEY)
        } finally {
            storage.clearRequestIdContext()
        }
    }

    @Test fun genuineStashRoundTripsThroughRealWriteAndReadPaths() {
        val secret = ByteArray(96) { (it * 7 + 3).toByte() }
        writeStash(secret)
        assertArrayEquals(
            "loadDkgSecret must return exactly what storeDkgSecret wrapped",
            secret,
            readStash()
        )
    }

    /**
     * The stash is a live share guard: a read failure (e.g. a spent cipher) must not
     * be treated as corruption and wipe it. A second read with a fresh authorized
     * cipher must still recover the same secret after one fails.
     */
    @Test fun failedReadLeavesStashRecoverable() {
        val secret = ByteArray(64) { it.toByte() }
        writeStash(secret)

        // A cipher queued under the wrong role is never consumed by the decrypt read,
        // so the read fails for want of a decrypt cipher — without touching the stash.
        val badRequest = UUID.randomUUID().toString()
        storage.setPendingCipher(badRequest, decryptCipher(), AndroidKeystoreStorage.CipherRole.ENCRYPT)
        storage.setRequestIdContext(badRequest)
        try {
            assertThrows(Exception::class.java) { storage.loadShareByKey(SECRET_KEY) }
        } finally {
            storage.clearRequestIdContext()
        }

        assertArrayEquals("stash must survive a failed read", secret, readStash())
    }

    private companion object {
        const val SECRET_KEY = "__keep_dkg_secret_v1"
        const val ALIAS = "keep_dkg_secret"
        val META = ShareMetadataInfo("dkg_pending", 0u, 0u, 0u, ByteArray(0), false)
    }
}
