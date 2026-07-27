package io.privkey.keep

import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import javax.crypto.Cipher

/**
 * Covers the NIP-55 approval-flow unhappy branches named in gh #396 (split of #376): biometric
 * authentication FAILURE and user CANCELLATION. These live inside the anonymous
 * [BiometricPrompt.AuthenticationCallback] objects in [BiometricHelper]; on BIOMETRIC_STRONG
 * hardware with no PIN fallback and no emulator injection, the real prompt fires them only from
 * hardware. [BiometricHelper.BiometricAuthenticator] is the seam that lets these tests drive the
 * callbacks deterministically without stubbing the outcome into a hollow pass. Each test asserts
 * the result the callback maps to, and for the crypto path that no [Cipher] escapes on a
 * non-success outcome (key use is gated).
 */
@RunWith(AndroidJUnit4::class)
class BiometricHelperInstrumentedTest {

    // Drives a single error outcome through the seam. The default executor is unused: the fake
    // resumes the callback synchronously, so the suspend call completes on the test thread.
    private fun erroringAuthenticator(errorCode: Int, message: String = "test-injected-error") =
        BiometricHelper.BiometricAuthenticator { _, _, callback ->
            callback.onAuthenticationError(errorCode, message)
        }

    // A syntactically valid Cipher for the crypto path's CryptoObject wrapper. It is never used:
    // the injected error resolves before onAuthenticationSucceeded, so the key is never touched.
    private fun uninitializedCipher(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")

    private inline fun withActivity(block: (FragmentActivity) -> Unit) {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var activity: FragmentActivity? = null
            scenario.onActivity { activity = it }
            block(activity ?: error("MainActivity was not available to the scenario"))
        }
    }

    @Test
    fun authenticateWithResult_genericError_mapsToFailed() = withActivity { activity ->
        val helper = BiometricHelper(
            activity,
            authenticator = erroringAuthenticator(BiometricPrompt.ERROR_TIMEOUT)
        )
        val result = runBlocking { helper.authenticateWithResult(forcePrompt = true) }
        assertEquals(
            "A non-lockout authentication error must map to FAILED (auth not granted)",
            BiometricHelper.AuthResult.FAILED,
            result
        )
    }

    @Test
    fun authenticateWithResult_lockout_mapsToLockout() = withActivity { activity ->
        val helper = BiometricHelper(
            activity,
            authenticator = erroringAuthenticator(BiometricPrompt.ERROR_LOCKOUT)
        )
        val result = runBlocking { helper.authenticateWithResult(forcePrompt = true) }
        assertEquals(BiometricHelper.AuthResult.LOCKOUT, result)
    }

    @Test
    fun authenticateWithResult_permanentLockout_mapsToLockoutPermanent() = withActivity { activity ->
        val helper = BiometricHelper(
            activity,
            authenticator = erroringAuthenticator(BiometricPrompt.ERROR_LOCKOUT_PERMANENT)
        )
        val result = runBlocking { helper.authenticateWithResult(forcePrompt = true) }
        assertEquals(BiometricHelper.AuthResult.LOCKOUT_PERMANENT, result)
    }

    @Test
    fun authenticateWithCrypto_userCancellation_returnsNullWithoutKeyUse() = withActivity { activity ->
        val helper = BiometricHelper(
            activity,
            authenticator = erroringAuthenticator(BiometricPrompt.ERROR_USER_CANCELED)
        )
        val cipher = runBlocking { helper.authenticateWithCrypto(uninitializedCipher()) }
        assertNull("User cancellation must yield no cipher (key use gated)", cipher)
    }

    @Test
    fun authenticateWithCrypto_negativeButton_returnsNullWithoutKeyUse() = withActivity { activity ->
        val helper = BiometricHelper(
            activity,
            authenticator = erroringAuthenticator(BiometricPrompt.ERROR_NEGATIVE_BUTTON)
        )
        val cipher = runBlocking { helper.authenticateWithCrypto(uninitializedCipher()) }
        assertNull("Negative-button cancellation must yield no cipher (key use gated)", cipher)
    }

    @Test
    fun authenticateWithCrypto_nonCancellationError_throwsWithoutKeyUse() = withActivity { activity ->
        val helper = BiometricHelper(
            activity,
            authenticator = erroringAuthenticator(BiometricPrompt.ERROR_LOCKOUT)
        )
        assertThrows(BiometricHelper.BiometricException::class.java) {
            runBlocking { helper.authenticateWithCrypto(uninitializedCipher()) }
        }
    }
}
