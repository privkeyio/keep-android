package io.privkey.keep.nip55

import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.test.ComposeTimeoutException
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.printToString
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.R
import io.privkey.keep.storage.PrefRead
import io.privkey.keep.storage.RelayAuthWhitelistStore
import io.privkey.keep.storage.corruptStoredValue
import io.privkey.keep.storage.forgetWriteProbe
import io.privkey.keep.storage.rawPrefs
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

    // The v2 rule, not the classic one. The screen loads its list in a LaunchedEffect
    // with an IO hop, and the classic rule resumes such a continuation on the IO thread,
    // writing the screen's state off the main thread. Under it the update now and then
    // never showed: the read finished with the right answer and the screen stayed on its
    // initial empty state. The v2 rule resumes on the main thread, as the app does, and
    // the failure has not recurred under it.
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

    /** What was staged, kept so a timeout can say whether it is still on disk. */
    private class Staged(val storedName: String, val corruptedValue: String)

    private fun stageUnreadableList(): Staged {
        val storedName = writeAndFindStoredName(context, RelayAuthWhitelistStore.PREFS_NAME) {
            RelayAuthWhitelistStore(context).add("wss://$STAGED_HOST")
        }
        corruptStoredValue(context, RelayAuthWhitelistStore.PREFS_NAME, storedName)
        val corrupted = rawPrefs(context, RelayAuthWhitelistStore.PREFS_NAME).getString(storedName, null)
        return Staged(storedName, checkNotNull(corrupted) { "the staged entry vanished as it was written" })
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
        val staged = stageUnreadableList()
        showScreen(gateReset = { /* never runs the action */ })

        awaitUnreadable(staged)
        compose.onNodeWithText(resetText).performClick()
        val confirm = context.getString(R.string.connections_nip55_relay_auth_whitelist_reset_confirm)
        awaitText(confirm)
        compose.onNodeWithText(confirm).performClick()

        compose.waitForIdle()
        assertEquals(PrefRead.Unreadable, RelayAuthWhitelistStore(context).readHosts())

        forgetWriteProbe(context, RelayAuthWhitelistStore.PREFS_NAME)
    }

    /** The store the screen under test holds, so a timeout can ask it directly. */
    private var screenStore: RelayAuthWhitelistStore? = null

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
            val store = remember { RelayAuthWhitelistStore(context).also { screenStore = it } }
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

    // A generous bound, since the CI emulator runs these at about half local speed and
    // waitUntil returns as soon as the text appears, so it costs nothing on a pass.
    private fun awaitText(text: String) = compose.waitUntil(timeoutMillis = AWAIT_MS) {
        compose.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty()
    }

    /**
     * Waits for the unreadable state, and on a timeout fails with what was actually there.
     *
     * The report says whether the damaged entry is still damaged in the process's copy
     * of the file, what the screen's own store and a fresh store each answer now, and
     * which state the screen is showing, so a failure points at the file, the store or
     * the screen.
     */
    private fun awaitUnreadable(staged: Staged) {
        try {
            awaitText(unreadableText)
        } catch (e: ComposeTimeoutException) {
            throw AssertionError(describe(staged), e)
        }
    }

    /** One store's answer for the list, in words. */
    private fun describeRead(store: RelayAuthWhitelistStore): String =
        runCatching { store.readHosts() }.fold(
            onSuccess = { read ->
                when (read) {
                    is PrefRead.Found -> "Found with ${read.value.size} host(s)"
                    PrefRead.Absent -> "Absent"
                    PrefRead.Unreadable -> "Unreadable"
                }
            },
            onFailure = { "a raised ${it::class.simpleName}" }
        )

    private fun describe(staged: Staged): String {
        val raw = rawPrefs(context, RelayAuthWhitelistStore.PREFS_NAME)
        val onDisk = raw.getString(staged.storedName, null)
        val diskState = when (onDisk) {
            null -> "The damaged entry is gone from the process's copy of the file"
            staged.corruptedValue -> "The damaged entry is still in the process's copy of the file, unchanged"
            else -> "The damaged entry was rewritten in the process's copy of the file"
        }
        val screenRead = screenStore?.let(::describeRead) ?: "nothing, it was never created"
        val freshRead = describeRead(RelayAuthWhitelistStore(context))
        val shown = listOf("unreadable" to unreadableText, "empty" to emptyText, "a host row" to STAGED_HOST)
            .filter { (_, text) -> compose.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty() }
            .map { it.first }
            .ifEmpty { listOf("none of the known states") }
        val tree = runCatching { compose.onRoot().printToString() }
            .getOrElse { "unavailable: ${it::class.simpleName}" }
        return "The unreadable state never appeared. $diskState, with ${raw.all.size} raw " +
            "entries in that copy; the screen's own store answers $screenRead; a fresh store answers " +
            "$freshRead; the screen shows " +
            "${shown.joinToString()}.\n$tree"
    }

    @Test
    fun anUnreadableListIsReportedRatherThanShownAsEmpty() {
        val staged = stageUnreadableList()
        showScreen()

        awaitUnreadable(staged)
        compose.onNodeWithText(unreadableText).assertIsDisplayed()
        compose.onNodeWithText(emptyText).assertDoesNotExist()
        // The input is gone too: every add in this state fails, and it fails with the
        // same signal a malformed relay URL gets.
        compose.onNodeWithText(
            context.getString(R.string.connections_nip55_relay_auth_whitelist_add)
        ).assertDoesNotExist()

        forgetWriteProbe(context, RelayAuthWhitelistStore.PREFS_NAME)
    }

    // An empty list is reported as empty, not as a fault. This also matches the screen
    // before its read lands, since it opens on an empty list, so the listed-host case
    // below is the control that proves the read.
    @Test
    fun anEmptyListIsStillReportedAsEmpty() {
        showScreen()

        awaitText(emptyText)
        compose.onNodeWithText(emptyText).assertIsDisplayed()
        compose.onNodeWithText(unreadableText).assertDoesNotExist()
        compose.onNodeWithText(resetText).assertDoesNotExist()
    }

    // The readable control. A listed host appears only once the read has landed, so the
    // unreadable assertions above cannot pass on a screen that reports a fault whatever
    // it reads.
    @Test
    fun aReadableListShowsItsHostsRatherThanAFault() {
        RelayAuthWhitelistStore(context).add("wss://$STAGED_HOST")
        showScreen()

        awaitText(STAGED_HOST)
        compose.onNodeWithText(STAGED_HOST).assertIsDisplayed()
        compose.onNodeWithText(unreadableText).assertDoesNotExist()
        compose.onNodeWithText(emptyText).assertDoesNotExist()
        compose.onNodeWithText(resetText).assertDoesNotExist()
    }

    // Declining has to leave the list where it is. Without this, a confirmation that
    // deleted on either answer would pass every other case here.
    @Test
    fun decliningTheResetLeavesTheListAlone() {
        val staged = stageUnreadableList()
        showScreen()

        awaitUnreadable(staged)
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
        val staged = stageUnreadableList()
        showScreen()

        awaitUnreadable(staged)
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

    private fun submit(relay: String) {
        compose.onNodeWithText(context.getString(R.string.connections_nip55_relay_auth_whitelist_add_label))
            .performTextInput(relay)
        compose.onNodeWithText(context.getString(R.string.connections_nip55_relay_auth_whitelist_add)).performClick()
    }

    // A bad host and a full list used to show the same bare error outline.
    @Test
    fun aHostThatIsNotARelaySaysSo() {
        showScreen()
        awaitText(emptyText)

        submit("wss://")

        awaitText(context.getString(R.string.connections_nip55_relay_auth_whitelist_invalid_host))
        compose.onNodeWithText(context.getString(R.string.connections_nip55_relay_auth_whitelist_full)).assertDoesNotExist()
    }

    @Test
    fun aFullListSaysSoRatherThanBlamingTheHost() {
        val store = RelayAuthWhitelistStore(context)
        repeat(256) { store.add("relay$it.example.com") }
        showScreen()
        awaitText("relay0.example.com")

        submit("wss://overflow.example.com")

        awaitText(context.getString(R.string.connections_nip55_relay_auth_whitelist_full))
        compose.onNodeWithText(context.getString(R.string.connections_nip55_relay_auth_whitelist_invalid_host)).assertDoesNotExist()
    }

    private companion object {
        const val AWAIT_MS = 15_000L
        // Normalized form, which is what the store keeps and the screen renders.
        const val STAGED_HOST = "relay.example.com"
    }
}
