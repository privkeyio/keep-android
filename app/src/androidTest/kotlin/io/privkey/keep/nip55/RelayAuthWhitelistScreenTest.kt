package io.privkey.keep.nip55

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.R
import io.privkey.keep.storage.RelayAuthWhitelistStore
import io.privkey.keep.storage.corruptStoredValue
import io.privkey.keep.storage.forgetWriteProbe
import io.privkey.keep.storage.writeAndFindStoredName
import io.privkey.keep.ui.theme.KeepAndroidTheme
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * What this screen says about a whitelist it could not read, and the way back from it.
 *
 * The gate auto-rejects every kind 22242 request while the list is unreadable, so a
 * screen reporting "no relays whitelisted" there states the opposite of what is being
 * enforced. It is also the only place the state can be repaired from: add refuses to
 * write over a list it could not read, and there are no rows to remove.
 *
 * The fault is staged on disk rather than injected, so these run against the same
 * undecryptable value the store would meet on a device that lost its Keystore alias.
 */
@RunWith(AndroidJUnit4::class)
class RelayAuthWhitelistScreenTest {

    // createComposeRule() is deprecated in favor of the v2 API; the classic rule
    // is intentional here, and the project builds with -Werror.
    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private val unreadableText
        get() = context.getString(R.string.connections_nip55_relay_auth_whitelist_unreadable)
    private val emptyText
        get() = context.getString(R.string.connections_nip55_relay_auth_whitelist_empty)
    private val resetText
        get() = context.getString(R.string.connections_nip55_relay_auth_whitelist_reset)

    @Before
    fun setup() {
        clear()
    }

    @After
    fun teardown() {
        clear()
    }

    private fun clear() {
        context.deleteSharedPreferences(RelayAuthWhitelistStore.PREFS_NAME)
    }

    private fun stageUnreadableList() {
        val storedName = writeAndFindStoredName(context, RelayAuthWhitelistStore.PREFS_NAME) {
            RelayAuthWhitelistStore(context).add("wss://relay.example.com")
        }
        corruptStoredValue(context, RelayAuthWhitelistStore.PREFS_NAME, storedName)
    }

    private fun showScreen() {
        compose.setContent {
            KeepAndroidTheme {
                RelayAuthWhitelistScreen(RelayAuthWhitelistStore(context), onDismiss = {})
            }
        }
    }

    private fun awaitText(text: String) = compose.waitUntil(timeoutMillis = 5_000) {
        compose.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty()
    }

    @Test
    fun anUnreadableListIsReportedRatherThanShownAsEmpty() {
        stageUnreadableList()
        showScreen()

        awaitText(unreadableText)
        compose.onNodeWithText(unreadableText).assertIsDisplayed()
        compose.onNodeWithText(emptyText).assertDoesNotExist()
        // The input is gone too: every add in this state fails, and it fails with the
        // same signal a malformed relay URL gets.
        compose.onNodeWithText(
            context.getString(R.string.connections_nip55_relay_auth_whitelist_add)
        ).assertDoesNotExist()

        forgetWriteProbe(context, RelayAuthWhitelistStore.PREFS_NAME)
    }

    // The readable case, so the assertions above cannot pass on a screen that reports a
    // fault whatever it reads.
    @Test
    fun anEmptyListIsStillReportedAsEmpty() {
        showScreen()

        awaitText(emptyText)
        compose.onNodeWithText(emptyText).assertIsDisplayed()
        compose.onNodeWithText(unreadableText).assertDoesNotExist()
        compose.onNodeWithText(resetText).assertDoesNotExist()
    }

    @Test
    fun resettingAnUnreadableListClearsItAndTheScreenRecovers() {
        stageUnreadableList()
        showScreen()

        awaitText(unreadableText)
        compose.onNodeWithText(resetText).performClick()

        // Confirmed rather than done on the first tap: an unreadable list can be a
        // transient Keystore fault, and the reset deletes whatever it still holds.
        val confirm = context.getString(R.string.connections_nip55_relay_auth_whitelist_reset_confirm)
        awaitText(confirm)
        compose.onNodeWithText(confirm).performClick()

        // Back to the state of a whitelist nobody has configured, which is the gate
        // deferring to per-app resolution rather than rejecting every relay.
        awaitText(emptyText)
        compose.onNodeWithText(emptyText).assertIsDisplayed()
        compose.onNodeWithText(unreadableText).assertDoesNotExist()
        compose.onNodeWithText(
            context.getString(R.string.connections_nip55_relay_auth_whitelist_reset_failed)
        ).assertDoesNotExist()

        forgetWriteProbe(context, RelayAuthWhitelistStore.PREFS_NAME)
    }
}
