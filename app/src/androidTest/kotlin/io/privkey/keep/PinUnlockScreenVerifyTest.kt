package io.privkey.keep

import androidx.compose.runtime.remember
import androidx.compose.ui.semantics.AccessibilityAction
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsPropertyKey
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.text.AnnotatedString
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.storage.KeystoreEncryptedPrefs
import io.privkey.keep.storage.PinStore
import io.privkey.keep.ui.theme.KeepAndroidTheme
import java.util.concurrent.atomic.AtomicInteger
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The PIN check on the unlock screen runs off the main thread, one at a time.
 *
 * Each check is PBKDF2 at 120k iterations, so the result arrives on IO, which compose
 * idling does not track: these wait for its effect rather than for idle.
 */
@RunWith(AndroidJUnit4::class)
class PinUnlockScreenVerifyTest {

    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val unlockLabel get() = context.getString(R.string.pin_unlock_button)
    private val unlocks = AtomicInteger()
    private lateinit var store: PinStore

    @Before
    fun setup() {
        context.deleteSharedPreferences(PinStore.PREFS_NAME)
        store = PinStore(context)
        assertTrue(store.setPin(GOOD_PIN))
        store.invalidateSession()
    }

    @After
    fun teardown() {
        context.deleteSharedPreferences(PinStore.PREFS_NAME)
    }

    private fun showScreen() {
        compose.setContent {
            val pins = remember { store }
            KeepAndroidTheme {
                PinUnlockScreen(
                    pinStore = pins,
                    onUnlocked = { unlocks.incrementAndGet() },
                    authorizePinRemoval = { false }
                )
            }
        }
    }

    private fun waitFor(timeoutMs: Long = AWAIT_MS, condition: () -> Boolean) = compose.waitUntil(timeoutMs, condition)

    private fun incorrect(spent: Int) =
        String.format(context.getString(R.string.pin_unlock_error_incorrect), PinStore.MAX_FAILED_ATTEMPTS - spent)

    @Test
    fun theRightPinUnlocks() {
        showScreen()
        compose.onNode(hasSetTextAction()).performTextInput(GOOD_PIN)
        compose.onNodeWithText(unlockLabel).performClick()

        waitFor { unlocks.get() >= 1 }
        compose.runOnIdle { assertEquals(1, unlocks.get()) }
    }

    @Test
    fun aWrongPinReportsTheRemainingAttempts() {
        showScreen()
        compose.onNode(hasSetTextAction()).performTextInput(WRONG_PIN)
        compose.onNodeWithText(unlockLabel).performClick()

        waitFor { compose.onAllNodesWithText(incorrect(1)).fetchSemanticsNodes().isNotEmpty() }
        assertEquals(0, unlocks.get())
        assertEquals(PinStore.MAX_FAILED_ATTEMPTS - 1, store.getRemainingAttempts())
    }

    // The tap returns before any attempt is spent, which it cannot if the check runs
    // inside it on the main thread. Read from the file rather than through the store,
    // whose lock the check holds once it starts on IO; a wrong PIN there runs three
    // PBKDF2 rounds before it counts, so a read straight after the tap still sees none.
    @Test
    fun theCheckDoesNotRunOnTheMainThread() {
        showScreen()
        compose.onNode(hasSetTextAction()).performTextInput(WRONG_PIN)
        val tap = action(SemanticsActions.OnClick, unlockLabel)
        val counter = KeystoreEncryptedPrefs.create(context, PinStore.PREFS_NAME)
        var spentWhenTapReturned = -1
        compose.runOnUiThread {
            tap()
            spentWhenTapReturned = counter.getInt(FAILED_ATTEMPTS, 0)
        }

        assertEquals(0, spentWhenTapReturned)
        waitFor { compose.onAllNodesWithText(incorrect(1)).fetchSemanticsNodes().isNotEmpty() }
    }

    // A new PIN typed and submitted while a check is still running is ignored, not
    // queued behind it, so it cannot spend a second attempt.
    @Test
    fun aSubmitWhileACheckIsRunningIsIgnored() {
        showScreen()
        compose.onNode(hasSetTextAction()).performTextInput(WRONG_PIN)
        val tap = action(SemanticsActions.OnClick, unlockLabel)
        val field = compose.onNode(hasSetTextAction()).fetchSemanticsNode().config[SemanticsActions.SetText].action!!
        val started = System.nanoTime()
        compose.runOnUiThread {
            tap()
            field(AnnotatedString(OTHER_WRONG_PIN))
            tap()
        }

        waitFor { compose.onAllNodesWithText(incorrect(1)).fetchSemanticsNodes().isNotEmpty() }
        // A queued second check would start only once the first returned, so give it
        // well over the time the first one took before calling it absent.
        val firstCheckMs = (System.nanoTime() - started) / 1_000_000
        val secondSpent = runCatching {
            waitFor(maxOf(MIN_SECOND_CHECK_MS, 3 * firstCheckMs)) {
                store.getRemainingAttempts() < PinStore.MAX_FAILED_ATTEMPTS - 1
            }
        }.isSuccess
        assertFalse("a second submit must not spend an attempt", secondSpent)
    }

    private fun action(key: SemanticsPropertyKey<AccessibilityAction<() -> Boolean>>, label: String) =
        compose.onNodeWithText(label).fetchSemanticsNode().config[key].action!!

    private companion object {
        const val GOOD_PIN = "2580"
        const val WRONG_PIN = "1357"
        const val OTHER_WRONG_PIN = "1470"
        const val FAILED_ATTEMPTS = "failed_attempts"
        const val MIN_SECOND_CHECK_MS = 2_000L
        const val AWAIT_MS = 15_000L
    }
}
