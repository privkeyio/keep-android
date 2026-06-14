package io.privkey.keep

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.ui.theme.KeepAndroidTheme
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * User-flow tests for the lock screen. The screen hoists its authentication via
 * [BiometricUnlockScreen]'s `onAuthenticate`/`onUnlocked` callbacks, so the real
 * unlock branch is exercised here with a fake authenticator. No system biometric
 * prompt and no production bypass flag are needed.
 */
@RunWith(AndroidJUnit4::class)
class BiometricUnlockScreenTest {

    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun successfulAuth_unlocks() {
        var unlocked = false

        compose.setContent {
            KeepAndroidTheme {
                BiometricUnlockScreen(
                    onAuthenticate = { BiometricHelper.AuthResult.SUCCESS },
                    onUnlocked = { unlocked = true }
                )
            }
        }

        compose.waitUntil(timeoutMillis = 2_000) { unlocked }
        assertTrue("A successful auth should unlock", unlocked)
    }

    @Test
    fun failedAuth_staysLockedAndOffersRetry() {
        var unlocked = false

        compose.setContent {
            KeepAndroidTheme {
                BiometricUnlockScreen(
                    onAuthenticate = { BiometricHelper.AuthResult.FAILED },
                    onUnlocked = { unlocked = true }
                )
            }
        }

        compose.onNodeWithText(context.getString(R.string.biometric_unlock_try_again))
            .assertIsDisplayed()
        assertFalse("A failed auth must not unlock", unlocked)
    }

    @Test
    fun lockout_showsLockoutMessage() {
        compose.setContent {
            KeepAndroidTheme {
                BiometricUnlockScreen(
                    onAuthenticate = { BiometricHelper.AuthResult.LOCKOUT },
                    onUnlocked = { }
                )
            }
        }

        compose.onNodeWithText(context.getString(R.string.biometric_unlock_lockout))
            .assertIsDisplayed()
    }

    @Test
    fun permanentLockout_showsPermanentMessageAndStaysLocked() {
        var unlocked = false

        compose.setContent {
            KeepAndroidTheme {
                BiometricUnlockScreen(
                    onAuthenticate = { BiometricHelper.AuthResult.LOCKOUT_PERMANENT },
                    onUnlocked = { unlocked = true }
                )
            }
        }

        compose.onNodeWithText(context.getString(R.string.biometric_unlock_lockout_permanent))
            .assertIsDisplayed()
        assertFalse("A permanent lockout must not unlock", unlocked)
    }
}
