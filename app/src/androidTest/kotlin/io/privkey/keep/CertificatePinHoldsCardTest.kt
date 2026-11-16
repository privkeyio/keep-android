package io.privkey.keep

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.CertificatePinHolds
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A relay whose pin was removed stays disconnected until the user acts, so the card has to
 * show it and offer the way back for each one, including the case where the core could not
 * read which hosts it holds.
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
    private val trustHost get() = context.getString(R.string.settings_cert_pins_trust_host)
    private val heldTitle get() = context.getString(R.string.settings_cert_pins_held_title)

    private fun show(holds: CertificatePinHolds?, trusted: MutableList<String>) = compose.setContent {
        KeepAndroidTheme {
            CertificatePinsCard(
                pins = emptyList(),
                holds = holds,
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
        show(CertificatePinHolds(listOf("relay.one.com", "relay.two.com"), false, emptyList()), trusted)

        compose.onNodeWithText(heldTitle).assertIsDisplayed()
        compose.onNodeWithText("relay.two.com").assertIsDisplayed()
        compose.onAllNodesWithText(trustNext)[1].performClick()
        assertEquals(listOf("relay.two.com"), trusted)
        assertEquals(0, compose.onAllNodesWithText(trustHost).fetchSemanticsNodes().size)
    }

    @Test
    fun unreadableHoldsOfferToTrustAHostByName() {
        val trusted = mutableListOf<String>()
        show(CertificatePinHolds(emptyList(), true, emptyList()), trusted)

        compose.onNodeWithText(context.getString(R.string.settings_cert_pins_held_all_text)).assertIsDisplayed()
        compose.onNodeWithText(trustHost).performClick()
        compose.onNodeWithText(context.getString(R.string.settings_cert_pins_stage_host_label)).performTextInput(" relay.example.com ")
        compose.onNodeWithText(trustNext).performClick()
        assertEquals(listOf("relay.example.com"), trusted)
    }

    @Test
    fun nothingHeldShowsNoSection() {
        show(CertificatePinHolds(emptyList(), false, emptyList()), mutableListOf())
        assertEquals(0, compose.onAllNodesWithText(heldTitle).fetchSemanticsNodes().size)
    }
}
