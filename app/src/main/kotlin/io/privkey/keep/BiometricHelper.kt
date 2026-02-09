package io.privkey.keep

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
        title: String = "Authenticate",
        subtitle: String = "Confirm your identity",
        negativeButtonText: String = "Cancel",
        forcePrompt: Boolean = false
    ): Boolean = authenticateWithResult(title, subtitle, negativeButtonText, forcePrompt) == AuthResult.SUCCESS

    suspend fun authenticateWithResult(
        title: String = "Authenticate",
        subtitle: String = "Confirm your identity",
        negativeButtonText: String = "Cancel",
        forcePrompt: Boolean = false
    ): AuthResult {
        if (!forcePrompt && timeoutStore?.requiresBiometric() == false) {
            return AuthResult.SUCCESS
        }
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

            BiometricPrompt(activity, executor, callback)
                .authenticate(buildPromptInfo(title, subtitle, negativeButtonText))
        }
    }

    suspend fun authenticateWithCrypto(
        cipher: Cipher,
        title: String = "Authenticate",
        subtitle: String = "Confirm your identity",
        negativeButtonText: String = "Cancel"
    ): Cipher? = suspendCoroutine { continuation ->
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
            buildPromptInfo(title, subtitle, negativeButtonText),
            BiometricPrompt.CryptoObject(cipher)
        )
    }

    private fun buildPromptInfo(
        title: String,
        subtitle: String,
        negativeButtonText: String
    ): BiometricPrompt.PromptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle(subtitle)
        .setNegativeButtonText(negativeButtonText)
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .build()

    class BiometricException(val errorCode: Int, message: String) : Exception(message)
}
