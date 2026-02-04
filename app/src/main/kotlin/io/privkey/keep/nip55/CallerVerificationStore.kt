package io.privkey.keep.nip55

import android.content.Context
import android.content.pm.PackageManager
import io.privkey.keep.storage.KeystoreEncryptedPrefs
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

class CallerVerificationStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "nip55_caller_verification"
        private const val KEY_PREFIX_SIGNATURE = "sig_"
        private const val NONCE_EXPIRY_MS = 5 * 60 * 1000L
    }

    private data class NonceData(val packageName: String, val expiresAt: Long)
    private val activeNonces = ConcurrentHashMap<String, NonceData>()

    private val prefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    private val packageManager = context.packageManager

    fun getPackageSignatureHash(packageName: String): String? {
        return try {
            val packageInfo = packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNING_CERTIFICATES
            )
            val signingInfo = packageInfo.signingInfo ?: return null
            val signatures = if (signingInfo.hasMultipleSigners()) {
                signingInfo.apkContentsSigners
            } else {
                signingInfo.signingCertificateHistory
            }
            if (signatures.isNullOrEmpty()) return null

            val sortedSignatureBytes = signatures
                .map { it.toByteArray() }
                .sortedWith { a, b ->
                    val minLen = minOf(a.size, b.size)
                    for (i in 0 until minLen) {
                        val cmp = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
                        if (cmp != 0) return@sortedWith cmp
                    }
                    a.size - b.size
                }

            val digest = MessageDigest.getInstance("SHA-256")
            sortedSignatureBytes.forEach { digest.update(it) }
            digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        } catch (_: Exception) {
            null
        }
    }

    private fun getTrustedSignature(packageName: String): String? =
        prefs.getString(KEY_PREFIX_SIGNATURE + packageName, null)

    fun verifyOrTrust(packageName: String): VerificationResult {
        val currentSignature = getPackageSignatureHash(packageName)
            ?: return VerificationResult.NotInstalled

        val trustedSignature = getTrustedSignature(packageName)
        return when {
            trustedSignature == null -> VerificationResult.FirstUseRequiresApproval(currentSignature)
            MessageDigest.isEqual(trustedSignature.toByteArray(Charsets.UTF_8), currentSignature.toByteArray(Charsets.UTF_8)) -> VerificationResult.Verified(currentSignature)
            else -> VerificationResult.SignatureMismatch(trustedSignature, currentSignature)
        }
    }

    fun trustPackage(packageName: String, signatureHash: String) {
        prefs.edit().putString(KEY_PREFIX_SIGNATURE + packageName, signatureHash).commit()
    }

    fun generateNonce(packageName: String): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        val nonce = bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        val expiresAt = System.currentTimeMillis() + NONCE_EXPIRY_MS
        activeNonces[nonce] = NonceData(packageName, expiresAt)
        return nonce
    }

    fun consumeNonce(nonce: String): NonceResult {
        val data = activeNonces.remove(nonce) ?: return NonceResult.Invalid
        return if (System.currentTimeMillis() > data.expiresAt) NonceResult.Expired else NonceResult.Valid(data.packageName)
    }

    fun cleanupExpiredNonces() {
        val now = System.currentTimeMillis()
        activeNonces.entries.removeIf { it.value.expiresAt < now }
    }

    sealed class VerificationResult {
        abstract val signatureHash: String?

        data class Verified(override val signatureHash: String) : VerificationResult()
        data class FirstUseRequiresApproval(override val signatureHash: String) : VerificationResult()
        data class SignatureMismatch(val expected: String, val actual: String) : VerificationResult() {
            override val signatureHash: String? = null
        }
        data object NotInstalled : VerificationResult() {
            override val signatureHash: String? = null
        }
    }

    sealed class NonceResult {
        data class Valid(val packageName: String) : NonceResult()
        data object Invalid : NonceResult()
        data object Expired : NonceResult()
    }
}
