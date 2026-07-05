package io.privkey.keep.nip55

import android.content.Context
import android.content.pm.PackageManager
import android.os.SystemClock
import android.util.Log
import io.privkey.keep.BuildConfig
import io.privkey.keep.storage.KeystoreEncryptedPrefs
import io.privkey.keep.storage.LegacyPrefsMigration
import io.privkey.keep.uniffi.Nip55CallerVerification
import io.privkey.keep.uniffi.Nip55NonceResult
import io.privkey.keep.uniffi.Nip55NonceStore
import io.privkey.keep.uniffi.nip55VerifyCaller
import java.security.MessageDigest

class CallerVerificationStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "nip55_caller_verification"
        private const val KEY_PREFIX_SIGNATURE = "sig_"
    }

    // The TOFU decision and the challenge-nonce lifecycle live in Rust
    // (keep-mobile nip55_caller); Android keeps only the PackageManager call and
    // the trusted-signature storage.
    private val nonceStore = Nip55NonceStore()

    private val prefs = run {
        val newPrefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        LegacyPrefsMigration.migrateIfNeeded(context, PREFS_NAME, newPrefs)
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
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.w("CallerVerificationStore", "Failed to get package signature for $packageName", e)
            null
        }
    }

    private fun getTrustedSignature(packageName: String): String? =
        prefs.getString(KEY_PREFIX_SIGNATURE + packageName, null)

    fun verifyOrTrust(packageName: String): VerificationResult =
        nip55VerifyCaller(getPackageSignatureHash(packageName), getTrustedSignature(packageName))
            .toVerificationResult()

    fun trustPackage(packageName: String, signatureHash: String) {
        prefs.edit().putString(KEY_PREFIX_SIGNATURE + packageName, signatureHash).commit()
    }

    fun clearAllTrust() {
        prefs.edit().clear().commit()
        nonceStore.clear()
    }

    // Nonce freshness is measured on the boot-time clock (elapsedRealtime, which
    // counts device suspend) so the 5-minute window holds across deep sleep.
    fun generateNonce(packageName: String): String =
        nonceStore.generate(packageName, SystemClock.elapsedRealtime().toULong())

    fun consumeNonce(nonce: String): NonceResult =
        nonceStore.consume(nonce, SystemClock.elapsedRealtime().toULong()).toNonceResult()

    fun cleanupExpiredNonces() = nonceStore.cleanupExpired(SystemClock.elapsedRealtime().toULong())

    sealed class VerificationResult {
        abstract val signatureHash: String?

        data class Verified(override val signatureHash: String) : VerificationResult() {
            override fun toString() = "Verified"
        }
        data class FirstUseRequiresApproval(override val signatureHash: String) : VerificationResult() {
            override fun toString() = "FirstUseRequiresApproval"
        }
        data class SignatureMismatch(val expected: String, val actual: String) : VerificationResult() {
            override val signatureHash: String? = null
            override fun toString() = "SignatureMismatch"
        }
        data object NotInstalled : VerificationResult() {
            override val signatureHash: String? = null
            override fun toString() = "NotInstalled"
        }
    }

    sealed class NonceResult {
        data class Valid(val packageName: String) : NonceResult()
        data object Invalid : NonceResult()
        data object Expired : NonceResult()
    }
}

private fun Nip55CallerVerification.toVerificationResult(): CallerVerificationStore.VerificationResult =
    when (this) {
        is Nip55CallerVerification.NotInstalled ->
            CallerVerificationStore.VerificationResult.NotInstalled
        is Nip55CallerVerification.FirstUseRequiresApproval ->
            CallerVerificationStore.VerificationResult.FirstUseRequiresApproval(signature)
        is Nip55CallerVerification.Verified ->
            CallerVerificationStore.VerificationResult.Verified(signature)
        is Nip55CallerVerification.SignatureMismatch ->
            CallerVerificationStore.VerificationResult.SignatureMismatch(expected, actual)
    }

private fun Nip55NonceResult.toNonceResult(): CallerVerificationStore.NonceResult =
    when (this) {
        is Nip55NonceResult.Valid -> CallerVerificationStore.NonceResult.Valid(packageName)
        is Nip55NonceResult.Invalid -> CallerVerificationStore.NonceResult.Invalid
        is Nip55NonceResult.Expired -> CallerVerificationStore.NonceResult.Expired
    }
