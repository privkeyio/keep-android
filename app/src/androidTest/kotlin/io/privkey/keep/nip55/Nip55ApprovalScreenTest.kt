package io.privkey.keep.nip55

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.R
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.Nip55DeclaredPermission
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * User-flow tests for the NIP-55 approval screen: the screen a user sees when an
 * external app asks Keep to sign. Guards against the approve/reject controls
 * disappearing, being renamed, or wiring to the wrong callback.
 */
@RunWith(AndroidJUnit4::class)
class Nip55ApprovalScreenTest {

    // createComposeRule() is deprecated in favor of the v2 API; the classic rule
    // is intentional here, and the project builds with -Werror.
    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun signEventRequest() = Nip55Request(
        requestType = Nip55RequestType.SIGN_EVENT,
        content = """{"kind":1,"content":"gm","tags":[]}""",
        pubkey = null,
        returnType = "signature",
        compressionType = "none",
        callbackUrl = null,
        id = "req-1",
        currentUser = null,
        permissions = null,
        kind = null,
        scope = null
    )

    @Test
    fun signEvent_approve_invokesCallbackWithJustThisTime() {
        var approved = false
        var duration: PermissionDuration? = null
        var bundle: List<Nip55DeclaredPermission>? = null

        compose.setContent {
            KeepAndroidTheme {
                ApprovalScreen(
                    request = signEventRequest(),
                    callerPackage = "com.example.client",
                    callerVerified = false,
                    onApprove = { d, b, _ -> approved = true; duration = d; bundle = b },
                    onReject = { _, _ -> }
                )
            }
        }

        compose.onNodeWithText(context.getString(R.string.connections_nip55_approve))
            .assertIsDisplayed()
            .performClick()
        compose.waitForIdle()

        assertTrue("onApprove should fire when Approve is tapped", approved)
        assertEquals(
            "Duration is forced to JUST_THIS_TIME when remember-choice is gated off " +
                "(here callerVerified=false and showFirstUseWarning=false)",
            PermissionDuration.JUST_THIS_TIME,
            duration
        )
        assertTrue("No declared permissions to grant for a bare sign_event", bundle!!.isEmpty())
    }

    @Test
    fun signEvent_reject_invokesCallback() {
        var rejected = false

        compose.setContent {
            KeepAndroidTheme {
                ApprovalScreen(
                    request = signEventRequest(),
                    callerPackage = "com.example.client",
                    callerVerified = false,
                    onApprove = { _, _, _ -> },
                    onReject = { _, _ -> rejected = true }
                )
            }
        }

        compose.onNodeWithText(context.getString(R.string.connections_nip55_reject))
            .assertIsDisplayed()
            .performClick()
        compose.waitForIdle()

        assertTrue("onReject should fire when Reject is tapped", rejected)
    }

    @Test
    fun approve_hidesBothButtons_soASecondTapCannotDoubleSubmit() {
        var approveCount = 0
        var rejectCount = 0

        compose.setContent {
            KeepAndroidTheme {
                ApprovalScreen(
                    request = signEventRequest(),
                    callerPackage = "com.example.client",
                    callerVerified = false,
                    onApprove = { _, _, _ -> approveCount++ },
                    onReject = { _, _ -> rejectCount++ }
                )
            }
        }

        compose.onNodeWithText(context.getString(R.string.connections_nip55_approve))
            .performClick()
        compose.waitForIdle()

        // isLoading flips true on the first tap and the footer swaps to a progress
        // spinner, so neither button remains in the tree: a second tap (or a Reject
        // after an Approve) can never commit a second decision.
        compose.onNodeWithText(context.getString(R.string.connections_nip55_approve))
            .assertDoesNotExist()
        compose.onNodeWithText(context.getString(R.string.connections_nip55_reject))
            .assertDoesNotExist()
        assertEquals("Approve fires exactly once", 1, approveCount)
        assertEquals("Reject must not fire after Approve", 0, rejectCount)
    }

    @Test
    fun reject_hidesBothButtons_soASecondTapCannotDoubleSubmit() {
        var approveCount = 0
        var rejectCount = 0

        compose.setContent {
            KeepAndroidTheme {
                ApprovalScreen(
                    request = signEventRequest(),
                    callerPackage = "com.example.client",
                    callerVerified = false,
                    onApprove = { _, _, _ -> approveCount++ },
                    onReject = { _, _ -> rejectCount++ }
                )
            }
        }

        compose.onNodeWithText(context.getString(R.string.connections_nip55_reject))
            .performClick()
        compose.waitForIdle()

        compose.onNodeWithText(context.getString(R.string.connections_nip55_reject))
            .assertDoesNotExist()
        compose.onNodeWithText(context.getString(R.string.connections_nip55_approve))
            .assertDoesNotExist()
        assertEquals("Reject fires exactly once", 1, rejectCount)
        assertEquals("Approve must not fire after Reject", 0, approveCount)
    }

    @Test
    fun firstUseCaller_canRememberChoice_showsDurationSelector() {
        compose.setContent {
            KeepAndroidTheme {
                ApprovalScreen(
                    request = signEventRequest(),
                    callerPackage = "com.example.client",
                    callerVerified = false,
                    showFirstUseWarning = true,
                    onApprove = { _, _, _ -> },
                    onReject = { _, _ -> }
                )
            }
        }

        compose.onNodeWithText(context.getString(R.string.connections_nip55_remember_choice))
            .assertIsDisplayed()
    }

    @Test
    fun unverifiedCaller_showsWarning() {
        compose.setContent {
            KeepAndroidTheme {
                ApprovalScreen(
                    request = signEventRequest(),
                    callerPackage = "com.example.client",
                    callerVerified = false,
                    onApprove = { _, _, _ -> },
                    onReject = { _, _ -> }
                )
            }
        }

        compose.onNodeWithText(context.getString(R.string.nip55_unverified_caller_warning))
            .assertIsDisplayed()
    }
}
