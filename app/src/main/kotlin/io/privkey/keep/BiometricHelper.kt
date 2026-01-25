package io.privkey.keep

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

class BiometricHelper(private val activity: FragmentActivity) {

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

    suspend fun authenticateWithCrypto(
        cipher: Cipher,
        title: String = "Authenticate",
        subtitle: String = "Confirm your identity",
        negativeButtonText: String = "Cancel"
    ): Cipher? = suspendCoroutine { continuation ->
        val executor = ContextCompat.getMainExecutor(activity)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                continuation.resume(result.cryptoObject?.cipher)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                    errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                ) {
                    continuation.resume(null)
                } else {
                    continuation.resumeWithException(
                        BiometricException(errorCode, errString.toString())
                    )
                }
            }

            override fun onAuthenticationFailed() {
            }
        }

        val biometricPrompt = BiometricPrompt(activity, executor, callback)
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(negativeButtonText)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }

    class BiometricException(val errorCode: Int, message: String) : Exception(message)
}
