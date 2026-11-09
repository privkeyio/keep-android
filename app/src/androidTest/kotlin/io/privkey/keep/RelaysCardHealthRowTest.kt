package io.privkey.keep

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.RelayHealth
import io.privkey.keep.uniffi.RelayHealthStatus
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RelaysCardHealthRowTest {

    // createComposeRule() is deprecated in favor of the v2 API; the classic rule
    // is intentional here, and the project builds with -Werror.
    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private val relay = "wss://relay.example.com"

    private fun render(relayHealth: List<RelayHealth>?) {
        compose.setContent {
            KeepAndroidTheme {
                RelaysCard(
                    relays = listOf(relay),
                    onAddRelay = {},
                    onRemoveRelay = {},
                    profileRelays = emptyList(),
                    onAddProfileRelay = {},
                    onRemoveProfileRelay = {},
                    relayConfigUnreadable = false,
                    onResetRelayConfig = {},
                    relayHealth = relayHealth
                )
            }
        }
    }

    private fun string(id: Int) = context.getString(id)

    @Test
    fun noPool_showsNotConnected() {
        render(relayHealth = null)

        compose.onNodeWithText("relay.example.com").assertIsDisplayed()
        compose.onNodeWithText(string(R.string.connections_relay_status_not_connected)).assertIsDisplayed()
    }

    @Test
    fun connectedWithRtt_showsLatency() {
        render(
            listOf(
                RelayHealth(
                    url = "$relay/",
                    status = RelayHealthStatus.CONNECTED,
                    lastConnectedMs = 1_700_000_000_000uL,
                    rttMs = 42uL,
                )
            )
        )

        val connected = string(R.string.connections_relay_status_connected)
        compose.onNodeWithText(
            context.getString(R.string.connections_relay_status_with_latency, connected, 42L)
        ).assertIsDisplayed()
    }

    @Test
    fun offlineAfterAConnection_showsLastConnected() {
        render(
            listOf(
                RelayHealth(
                    url = relay,
                    status = RelayHealthStatus.OFFLINE,
                    lastConnectedMs = 1_700_000_000_000uL,
                    rttMs = null,
                )
            )
        )

        val offline = string(R.string.connections_relay_status_offline)
        val prefix = context.getString(R.string.connections_relay_status_last_connected, offline, "")
        compose.onNodeWithText(prefix, substring = true).assertIsDisplayed()
    }

    @Test
    fun poolWithoutTheRelay_showsOffline() {
        render(
            listOf(
                RelayHealth(
                    url = "wss://other.example.com",
                    status = RelayHealthStatus.CONNECTED,
                    lastConnectedMs = 1_700_000_000_000uL,
                    rttMs = 10uL,
                )
            )
        )

        compose.onNodeWithText(string(R.string.connections_relay_status_offline)).assertIsDisplayed()
    }
}
