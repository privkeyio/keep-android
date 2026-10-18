package io.privkey.keep.nip55

import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.R
import io.privkey.keep.storage.PrefRead
import io.privkey.keep.storage.RelayAuthWhitelistStore
import io.privkey.keep.storage.corruptStoredValue
import io.privkey.keep.storage.forgetWriteProbe
import io.privkey.keep.storage.writeAndFindStoredName
import io.privkey.keep.ui.theme.KeepAndroidTheme
import kotlinx.coroutines.launch
import org.junit.After
import org.junit.Assert.assertEquals
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
 * The fault is staged on disk rather than injected, so these run against a real
 * undecryptable list entry. The other half of a lost Keystore alias, where the file's
 * own HMAC key will not decrypt either and resolving a name raises, is staged at the
 * store level in UnreadableReadGuardTest, since what it changes is which delete works
 * rather than what this screen shows.
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

    /**
     * The reset has to go through the gate, not around it.
     *
     * Every other case here supplies a gate that runs the action straight away, so a
     * change that moved the clear back into the screen's own scope would drop the auth
     * factor and still leave them all green. This one never invokes the action, which
     * is what a cancelled or unsatisfied auth does, and asserts nothing was deleted.
     */
    @Test
    fun theResetDoesNotHappenWithoutTheAuthGate() {
        stageUnreadableList()
        showScreen(gateReset = { /* never runs the action */ })

        awaitText(unreadableText)
        compose.onNodeWithText(resetText).performClick()
        val confirm = context.getString(R.string.connections_nip55_relay_auth_whitelist_reset_confirm)
        awaitText(confirm)
        compose.onNodeWithText(confirm).performClick()

        compose.waitForIdle()
        assertEquals(PrefRead.Unreadable, RelayAuthWhitelistStore(context).readHosts())

        forgetWriteProbe(context, RelayAuthWhitelistStore.PREFS_NAME)
    }

    /**
     * [gateReset] defaults to running the action, standing in for an auth factor that
     * was satisfied, so the cases below assert what the screen does after the gate
     * rather than what the gate does. Production supplies `requireAuthThen`.
     */
    private fun showScreen(gateReset: ((suspend () -> Unit) -> Unit)? = null) {
        compose.setContent {
            // Remembered, not rebuilt per recomposition: production hands this screen
            // the application's single store, and a fresh one each pass would give the
            // launched read and the button handlers different per-instance caches.
            val store = remember { RelayAuthWhitelistStore(context) }
            val scope = rememberCoroutineScope()
            val satisfiedGate: (suspend () -> Unit) -> Unit = { action -> scope.launch { action() } }
            KeepAndroidTheme {
                RelayAuthWhitelistScreen(
                    store = store,
                    onDismiss = {},
                    gateReset = gateReset ?: satisfiedGate
                )
            }
        }
    }

    // 15s, not 5s. The unreadable state appears only after a Keystore decrypt fails on an
    // IO dispatcher, which takes about 1s here and about 2s on the CI emulator, and on CI
    // it has also run past 5s: the same wait then passed in one test and timed out in two
    // others of the same run. waitUntil returns as soon as the text appears, so the larger
    // bound costs nothing on a pass, and a screen that never shows it still fails.
    private fun awaitText(text: String) = compose.waitUntil(timeoutMillis = AWAIT_MS) {
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

    // Declining has to leave the list where it is. Without this, a confirmation that
    // deleted on either answer would pass every other case here.
    @Test
    fun decliningTheResetLeavesTheListAlone() {
        stageUnreadableList()
        showScreen()

        awaitText(unreadableText)
        compose.onNodeWithText(resetText).performClick()
        val cancel = context.getString(R.string.common_cancel)
        awaitText(cancel)
        compose.onNodeWithText(cancel).performClick()

        compose.waitForIdle()
        compose.onNodeWithText(unreadableText).assertIsDisplayed()
        compose.onNodeWithText(emptyText).assertDoesNotExist()
        // And on disk, not just on screen.
        assertEquals(PrefRead.Unreadable, RelayAuthWhitelistStore(context).readHosts())

        forgetWriteProbe(context, RelayAuthWhitelistStore.PREFS_NAME)
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

    private companion object {
        const val AWAIT_MS = 15_000L
    }
}
