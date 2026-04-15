package io.privkey.keep

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.privkey.keep.storage.BiometricTimeoutStore
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

class BiometricHelper(
    private val activity: FragmentActivity,
    private val timeoutStore: BiometricTimeoutStore? = null
) {
    private val executor = ContextCompat.getMainExecutor(activity)

    enum class BiometricStatus {
        AVAILABLE,
        NOT_ENROLLED,
        NOT_AVAILABLE,
        ERROR
    }

    fun checkBiometricStatus(): BiometricStatus {
        val biometricManager = BiometricManager.from(activity)
        return when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricStatus.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricStatus.NOT_ENROLLED
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricStatus.NOT_AVAILABLE
            else -> BiometricStatus.ERROR
        }
    }

    enum class AuthResult {
        SUCCESS,
        FAILED,
        LOCKOUT,
        LOCKOUT_PERMANENT
    }

    suspend fun authenticate(
        title: String? = null,
        subtitle: String? = null,
        negativeButtonText: String? = null,
        forcePrompt: Boolean = false
    ): Boolean = authenticateWithResult(title, subtitle, negativeButtonText, forcePrompt) == AuthResult.SUCCESS

    suspend fun authenticateWithResult(
        title: String? = null,
        subtitle: String? = null,
        negativeButtonText: String? = null,
        forcePrompt: Boolean = false
    ): AuthResult {
        if (!forcePrompt && timeoutStore?.requiresBiometric() == false) {
            return AuthResult.SUCCESS
        }
        val promptInfo = resolvePromptInfo(title, subtitle, negativeButtonText)
        return suspendCoroutine { continuation ->
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    timeoutStore?.recordAuthentication()
                    continuation.resume(AuthResult.SUCCESS)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    val result = when (errorCode) {
                        BiometricPrompt.ERROR_LOCKOUT -> AuthResult.LOCKOUT
                        BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> AuthResult.LOCKOUT_PERMANENT
                        else -> AuthResult.FAILED
                    }
                    continuation.resume(result)
                }

                override fun onAuthenticationFailed() {}
            }

            BiometricPrompt(activity, executor, callback).authenticate(promptInfo)
        }
    }

    suspend fun authenticateWithCrypto(
        cipher: Cipher,
        title: String? = null,
        subtitle: String? = null,
        negativeButtonText: String? = null
    ): Cipher? {
        val promptInfo = resolvePromptInfo(title, subtitle, negativeButtonText)
        return suspendCoroutine { continuation ->
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    timeoutStore?.recordAuthentication()
                    continuation.resume(result.cryptoObject?.cipher)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    val isCancellation = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                    if (isCancellation) {
                        continuation.resume(null)
                    } else {
                        continuation.resumeWithException(
                            BiometricException(errorCode, errString.toString())
                        )
                    }
                }

                override fun onAuthenticationFailed() {}
            }

            BiometricPrompt(activity, executor, callback).authenticate(
                promptInfo,
                BiometricPrompt.CryptoObject(cipher)
            )
        }
    }

    private fun resolvePromptInfo(
        title: String?,
        subtitle: String?,
        negativeButtonText: String?
    ): BiometricPrompt.PromptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title ?: activity.getString(R.string.biometric_prompt_title))
        .setSubtitle(subtitle ?: activity.getString(R.string.biometric_prompt_subtitle))
        .setNegativeButtonText(negativeButtonText ?: activity.getString(R.string.biometric_prompt_negative_button))
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .build()

    class BiometricException(val errorCode: Int, message: String) : Exception(message)
    class BiometricNotReadyException(message: String) : Exception(message)

    companion object {
        fun getBiometricNotReadyMessage(context: Context, status: BiometricStatus): String = when (status) {
            BiometricStatus.AVAILABLE -> ""
            BiometricStatus.NOT_ENROLLED ->
                context.getString(R.string.biometric_not_ready_not_enrolled)
            BiometricStatus.NOT_AVAILABLE ->
                context.getString(R.string.biometric_not_ready_not_available)
            BiometricStatus.ERROR ->
                context.getString(R.string.biometric_not_ready_error)
        }

        fun requireBiometricReady(context: Context, status: BiometricStatus) {
            if (status == BiometricStatus.AVAILABLE) return
            throw BiometricNotReadyException(getBiometricNotReadyMessage(context, status))
        }
    }
}
