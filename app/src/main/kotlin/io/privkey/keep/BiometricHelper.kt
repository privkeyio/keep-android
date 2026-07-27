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

class BiometricHelper private constructor(
    private val activity: FragmentActivity,
    private val timeoutStore: BiometricTimeoutStore?,
    authenticator: BiometricAuthenticator?
) {
    /** Production constructor: always uses the real [BiometricPrompt]. */
    constructor(
        activity: FragmentActivity,
        timeoutStore: BiometricTimeoutStore? = null
    ) : this(activity, timeoutStore, null)

    private val executor = ContextCompat.getMainExecutor(activity)

    /**
     * Seam over [BiometricPrompt] so the approval-flow failure and cancellation branches can be
     * driven deterministically in tests. On these devices biometric is BIOMETRIC_STRONG with no
     * PIN fallback and no emulator injection, so the real prompt's callbacks are otherwise only
     * invoked by hardware. `internal` so it stays off the public API: production never injects one
     * (the public constructor above always uses the default), only same-module tests do via
     * [withAuthenticator].
     */
    internal fun interface BiometricAuthenticator {
        fun authenticate(
            promptInfo: BiometricPrompt.PromptInfo,
            cryptoObject: BiometricPrompt.CryptoObject?,
            callback: BiometricPrompt.AuthenticationCallback
        )
    }

    private val authenticator: BiometricAuthenticator = authenticator
        ?: BiometricAuthenticator { promptInfo, cryptoObject, callback ->
            val prompt = BiometricPrompt(activity, executor, callback)
            if (cryptoObject != null) {
                prompt.authenticate(promptInfo, cryptoObject)
            } else {
                prompt.authenticate(promptInfo)
            }
        }

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

            authenticator.authenticate(promptInfo, null, callback)
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

            authenticator.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher), callback)
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

        /** Test-only seam: build a helper whose prompt callbacks are driven by [authenticator]. */
        internal fun withAuthenticator(
            activity: FragmentActivity,
            timeoutStore: BiometricTimeoutStore?,
            authenticator: BiometricAuthenticator
        ): BiometricHelper = BiometricHelper(activity, timeoutStore, authenticator)
    }
}
