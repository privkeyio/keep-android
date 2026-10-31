package io.privkey.keep

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.ui.theme.KeepAndroidTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RelaysCardResetTest {

    // createComposeRule() is deprecated in favor of the v2 API; the classic rule
    // is intentional here, and the project builds with -Werror.
    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun render(unreadable: Boolean, onReset: () -> Unit) {
        compose.setContent {
            KeepAndroidTheme {
                RelaysCard(
                    relays = emptyList(),
                    onAddRelay = {},
                    onRemoveRelay = {},
                    profileRelays = emptyList(),
                    onAddProfileRelay = {},
                    onRemoveProfileRelay = {},
                    relayConfigUnreadable = unreadable,
                    onResetRelayConfig = onReset
                )
            }
        }
    }

    private fun text(id: Int) = compose.onNodeWithText(context.getString(id))

    @Test
    fun readableConfig_offersNoReset() {
        render(unreadable = false) {}

        text(R.string.connections_relays_reset_button).assertDoesNotExist()
        text(R.string.connections_relays_unreadable).assertDoesNotExist()
    }

    @Test
    fun cancel_doesNotReset() {
        var resets = 0
        render(unreadable = true) { resets++ }

        text(R.string.connections_relays_unreadable).assertIsDisplayed()
        text(R.string.connections_relays_reset_button).performClick()
        text(R.string.connections_relays_reset_title).assertIsDisplayed()
        text(R.string.common_cancel).performClick()

        text(R.string.connections_relays_reset_title).assertDoesNotExist()
        assertEquals(0, resets)
    }

    @Test
    fun aFaultThatClearsAndReturns_doesNotReopenTheDialog() {
        var unreadable by mutableStateOf(true)
        compose.setContent {
            KeepAndroidTheme {
                RelaysCard(
                    relays = emptyList(),
                    onAddRelay = {},
                    onRemoveRelay = {},
                    profileRelays = emptyList(),
                    onAddProfileRelay = {},
                    onRemoveProfileRelay = {},
                    relayConfigUnreadable = unreadable,
                    onResetRelayConfig = {}
                )
            }
        }

        text(R.string.connections_relays_reset_button).performClick()
        text(R.string.connections_relays_reset_title).assertIsDisplayed()
        unreadable = false
        compose.waitForIdle()
        text(R.string.connections_relays_reset_title).assertDoesNotExist()
        unreadable = true
        compose.waitForIdle()

        text(R.string.connections_relays_reset_button).assertIsDisplayed()
        text(R.string.connections_relays_reset_title).assertDoesNotExist()
    }

    @Test
    fun confirm_resetsOnce() {
        var resets = 0
        render(unreadable = true) { resets++ }

        text(R.string.connections_relays_reset_button).performClick()
        text(R.string.connections_relays_reset_confirm).performClick()

        compose.waitForIdle()
        text(R.string.connections_relays_reset_title).assertDoesNotExist()
        assertEquals(1, resets)
    }
}
