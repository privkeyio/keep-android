package io.privkey.keep.nip46

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.R
import io.privkey.keep.nip55.PermissionDuration
import io.privkey.keep.ui.theme.KeepAndroidTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The duration selector on this screen is labelled "Remember this decision", and
 * a refusal is a decision. It was only ever passed to approve, so a user who
 * chose a duration and then refused was asked again on the very next request.
 *
 * These pin the wiring rather than the rendering: what the reject button hands
 * back is what decides whether the signer remembers the refusal.
 */
@RunWith(AndroidJUnit4::class)
class Nip46RejectDurationTest {

    // createComposeRule() is deprecated in favor of the v2 API; the classic rule
    // is intentional here, and the project builds with -Werror.
    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun connectScreen(onReject: (PermissionDuration) -> Unit) {
        compose.setContent {
            KeepAndroidTheme {
                Nip46ApprovalScreen(
                    appName = "agent",
                    appPubkey = "abcd",
                    method = "connect",
                    eventKind = null,
                    eventContent = null,
                    isConnectRequest = true,
                    onApprove = { _, _ -> },
                    onReject = onReject
                )
            }
        }
    }

    private fun screen(onReject: (PermissionDuration) -> Unit) {
        compose.setContent {
            KeepAndroidTheme {
                Nip46ApprovalScreen(
                    appName = "agent",
                    appPubkey = "abcd",
                    method = "sign_event",
                    eventKind = 1,
                    eventContent = "gm",
                    onApprove = { _, _ -> },
                    onReject = onReject
                )
            }
        }
    }

    /**
     * The default records nothing. This is the negative that matters: if reject
     * forwarded anything other than the one-shot default, every ordinary "no"
     * would become a lasting silent block the user never asked for.
     */
    @Test
    fun rejecting_without_choosing_a_duration_reports_just_this_time() {
        var received: PermissionDuration? = null
        screen { received = it }

        compose.onNodeWithText(context.getString(R.string.connections_nip46_reject)).performClick()

        assertEquals(
            "an ordinary refusal must not record a window",
            PermissionDuration.JUST_THIS_TIME,
            received
        )
    }

    /**
     * And a deliberately chosen duration reaches the callback, which is what
     * lets the signer answer the retries instead of re-prompting.
     */
    @Test
    fun rejecting_after_choosing_a_duration_reports_that_duration() {
        var received: PermissionDuration? = null
        screen { received = it }

        // The selector is an ExposedDropdownMenuBox: the menu opens from the
        // read-only field showing the current selection, not from the label
        // above it. Clicking the label finds nothing and the menu never opens.
        compose.onNodeWithText(context.getString(R.string.permission_duration_just_this_time))
            .performClick()
        compose.onNodeWithText(context.getString(R.string.permission_duration_one_hour))
            .performClick()
        compose.onNodeWithText(context.getString(R.string.connections_nip46_reject)).performClick()

        assertEquals(
            "a chosen duration must reach the refusal, or the selector is decorative",
            PermissionDuration.ONE_HOUR,
            received
        )
    }

    /**
     * A connect request hides the selector and defaults it to Forever, so
     * forwarding that value would record a decision from a control the user
     * never saw. Harmless today only because Forever yields no window in
     * another crate; this pins it locally so a future release that supports
     * permanent refusals cannot turn a hidden default into a permanent block.
     */
    @Test
    fun rejecting_a_connect_request_reports_just_this_time() {
        var received: PermissionDuration? = null
        connectScreen { received = it }

        compose.onNodeWithText(context.getString(R.string.connections_nip46_reject)).performClick()

        assertEquals(
            "a hidden selector must not contribute a duration to a refusal",
            PermissionDuration.JUST_THIS_TIME,
            received
        )
    }
}
