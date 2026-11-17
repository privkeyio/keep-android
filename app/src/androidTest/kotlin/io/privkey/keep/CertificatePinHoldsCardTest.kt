package io.privkey.keep

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.ui.theme.KeepAndroidTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A relay whose pin was removed stays disconnected until the user acts, so the card has to
 * show it and offer the way back for each one, including the case where the core could not
 * read the pin records.
 */
@RunWith(AndroidJUnit4::class)
class CertificatePinHoldsCardTest {

    // createComposeRule() is deprecated in favor of the v2 API; the classic rule
    // is intentional here, and the project builds with -Werror.
    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val trustNext get() = context.getString(R.string.settings_cert_pins_trust_next)
    private val heldTitle get() = context.getString(R.string.settings_cert_pins_held_title)

    private fun show(held: List<String>?, trusted: MutableList<String>) = compose.setContent {
        KeepAndroidTheme {
            CertificatePinsCard(
                pins = emptyList(),
                held = held,
                onStagePin = { _, _ -> },
                onRetirePin = { _, _ -> },
                onTrustNextKey = { trusted += it },
                onClearAllPins = {},
            )
        }
    }

    @Test
    fun eachHeldHostOffersToTrustItsNextKey() {
        val trusted = mutableListOf<String>()
        show(listOf("wss://relay.one.com", "wss://relay.two.com"), trusted)

        compose.onNodeWithText(heldTitle).assertIsDisplayed()
        compose.onNodeWithText("wss://relay.two.com").assertIsDisplayed()
        compose.onAllNodesWithText(trustNext)[1].performClick()
        assertEquals("nothing is trusted before the warning is confirmed", emptyList<String>(), trusted)
        compose.onNodeWithText(context.getString(R.string.settings_cert_pins_trust_dialog_text, "wss://relay.two.com")).assertIsDisplayed()
        compose.onAllNodesWithText(trustNext).let { it[it.fetchSemanticsNodes().size - 1] }.performClick()
        assertEquals(listOf("wss://relay.two.com"), trusted)
    }

    @Test
    fun unreadableHoldsSayTheRecordsCouldNotBeRead() {
        show(null, mutableListOf())
        compose.onNodeWithText(context.getString(R.string.settings_cert_pins_held_unreadable)).assertIsDisplayed()
        assertEquals(0, compose.onAllNodesWithText(context.getString(R.string.settings_cert_pins_empty)).fetchSemanticsNodes().size)
    }

    @Test
    fun cancellingTheWarningTrustsNothing() {
        val trusted = mutableListOf<String>()
        show(listOf("wss://relay.one.com"), trusted)
        compose.onNodeWithText(trustNext).performClick()
        compose.onNodeWithText(context.getString(R.string.settings_cancel)).performClick()
        assertEquals(emptyList<String>(), trusted)
    }

    @Test
    fun theMismatchDialogWarnsBeforeClearingAndTrusting() {
        var cleared = 0
        compose.setContent {
            KeepAndroidTheme { PinMismatchDialog("relay.example.com", NEW_KEY, onClearAndRetry = { cleared++ }, onDismiss = {}) }
        }
        compose.onNodeWithText(context.getString(R.string.main_clear_pin_and_retry_text, "relay.example.com")).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.main_pin_mismatch_new_key, NEW_KEY)).assertIsDisplayed()
        assertEquals(0, cleared)
        compose.onNodeWithText(context.getString(R.string.main_clear_pin_and_retry)).performClick()
        assertEquals(1, cleared)
    }

    @Test
    fun nothingHeldShowsNoSection() {
        show(emptyList(), mutableListOf())
        assertEquals(0, compose.onAllNodesWithText(heldTitle).fetchSemanticsNodes().size)
        compose.onNodeWithText(context.getString(R.string.settings_cert_pins_empty)).assertIsDisplayed()
    }

    private companion object {
        const val NEW_KEY = "3b2f000000000000000000000000000000000000000000000000000000000a1c"
    }
}
