package io.privkey.keep.nip55

import android.content.Context
import android.content.pm.PackageManager
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest
import java.security.SecureRandom

class CallerVerificationStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "nip55_caller_verification"
        private const val KEY_PREFIX_SIGNATURE = "sig_"
        private const val KEY_PREFIX_NONCE = "nonce_"
        private const val NONCE_EXPIRY_MS = 5 * 60 * 1000L
    }

    private val prefs = run {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

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
            signatures?.firstOrNull()?.let { signature ->
                val digest = MessageDigest.getInstance("SHA-256")
                val hash = digest.digest(signature.toByteArray())
                hash.joinToString("") { "%02x".format(it) }
            }
        } catch (_: Exception) {
            null
        }
    }

    fun getTrustedSignature(packageName: String): String? =
        prefs.getString(KEY_PREFIX_SIGNATURE + packageName, null)

    fun setTrustedSignature(packageName: String, signatureHash: String) {
        prefs.edit().putString(KEY_PREFIX_SIGNATURE + packageName, signatureHash).apply()
    }

    fun clearTrustedSignature(packageName: String) {
        prefs.edit().remove(KEY_PREFIX_SIGNATURE + packageName).apply()
    }

    fun verifyOrTrust(packageName: String): VerificationResult {
        val currentSignature = getPackageSignatureHash(packageName)
            ?: return VerificationResult.NotInstalled

        val trustedSignature = getTrustedSignature(packageName)
        return when {
            trustedSignature == null -> {
                setTrustedSignature(packageName, currentSignature)
                VerificationResult.TrustedOnFirstUse(currentSignature)
            }
            trustedSignature == currentSignature -> VerificationResult.Verified(currentSignature)
            else -> VerificationResult.SignatureMismatch(trustedSignature, currentSignature)
        }
    }

    fun generateNonce(packageName: String): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        val nonce = bytes.joinToString("") { "%02x".format(it) }
        val expiresAt = System.currentTimeMillis() + NONCE_EXPIRY_MS
        prefs.edit().putString(KEY_PREFIX_NONCE + nonce, "$packageName:$expiresAt").apply()
        return nonce
    }

    fun consumeNonce(nonce: String): NonceResult {
        val value = prefs.getString(KEY_PREFIX_NONCE + nonce, null)
            ?: return NonceResult.Invalid

        prefs.edit().remove(KEY_PREFIX_NONCE + nonce).apply()

        val parts = value.split(":")
        if (parts.size != 2) return NonceResult.Invalid

        val packageName = parts[0]
        val expiresAt = parts[1].toLongOrNull() ?: return NonceResult.Invalid

        if (System.currentTimeMillis() > expiresAt) {
            return NonceResult.Expired
        }

        return NonceResult.Valid(packageName)
    }

    fun cleanupExpiredNonces() {
        val now = System.currentTimeMillis()
        val editor = prefs.edit()
        prefs.all.entries
            .filter { it.key.startsWith(KEY_PREFIX_NONCE) }
            .forEach { (key, value) ->
                val expiresAt = (value as? String)?.split(":")?.getOrNull(1)?.toLongOrNull()
                if (expiresAt != null && now > expiresAt) {
                    editor.remove(key)
                }
            }
        editor.apply()
    }

    sealed class VerificationResult {
        abstract val signatureHash: String?

        data class Verified(override val signatureHash: String) : VerificationResult()
        data class TrustedOnFirstUse(override val signatureHash: String) : VerificationResult()
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
