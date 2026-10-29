package io.privkey.keep.approver

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * The approver key: a P-256 signing key that never leaves the Keystore, each signature
 * needing a fresh strong biometric. Made anew for each pairing, since the attestation
 * challenge is per pairing code.
 */
internal object ApproverKey {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "keep_approver_p256"
    private const val PROBE_ALIAS = "keep_approver_strongbox_probe"
    private const val ALGORITHM = "SHA256withECDSA"

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    /** Replaces any approver key with a new one attested over [challenge]. */
    fun generate(context: Context, challenge: ByteArray) {
        delete()
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) &&
            strongBoxSigns()
        if (strongBox) {
            try {
                generate(challenge, strongBox = true)
                return
            } catch (e: StrongBoxUnavailableException) {
                delete()
            } catch (e: ProviderException) {
                delete()
            }
        }
        generate(challenge, strongBox = false)
    }

    private fun generate(challenge: ByteArray, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .setAttestationChallenge(challenge)
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    // Some StrongBox implementations make a key and then fail to use it, so a throwaway key
    // with the same algorithm, without user authentication, must sign before StrongBox is used.
    private fun strongBoxSigns(): Boolean = try {
        val spec = KeyGenParameterSpec.Builder(PROBE_ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(true)
            .build()
        val pair = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
        Signature.getInstance(ALGORITHM).run {
            initSign(pair.private)
            update(ByteArray(32))
            sign()
        }
        true
    } catch (e: Exception) {
        false
    } finally {
        runCatching { keyStore().deleteEntry(PROBE_ALIAS) }
    }

    /** The public key as 33 bytes, compressed SEC1. */
    fun publicKey(): ByteArray {
        val key = keyStore().getCertificate(ALIAS)?.publicKey as? ECPublicKey
            ?: throw IllegalStateException("no approver key")
        return compress(key.w.affineX, key.w.affineY)
    }

    /** The attestation chain, DER, leaf first. */
    fun attestation(): List<ByteArray> =
        keyStore().getCertificateChain(ALIAS)?.map { it.encoded }
            ?: throw IllegalStateException("no approver key")

    /**
     * A Signature ready for the biometric prompt to unlock. Throws
     * [android.security.keystore.KeyPermanentlyInvalidatedException] once a biometric
     * enrollment has destroyed the key.
     */
    fun signer(): Signature {
        val key = keyStore().getKey(ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("no approver key")
        return Signature.getInstance(ALGORITHM).apply { initSign(key) }
    }

    fun delete() {
        runCatching { keyStore().deleteEntry(ALIAS) }
    }

    internal fun compress(x: BigInteger, y: BigInteger): ByteArray {
        val xBytes = x.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        val out = ByteArray(33)
        out[0] = if (y.testBit(0)) 0x03 else 0x02
        xBytes.copyInto(out, 33 - xBytes.size)
        return out
    }
}
