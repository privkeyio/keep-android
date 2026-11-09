package io.privkey.keep

import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.espresso.Espresso
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.ui.theme.KeepAndroidTheme
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PinPromptDialogTest {

    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val verdict = CompletableDeferred<Boolean>()
    private val verifyCalls = AtomicInteger()
    private val dismissCalls = AtomicInteger()
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val cancel = context.getString(R.string.settings_cancel)

    // The check resumes off the test thread, on IO for the settings card, which
    // compose idling does not track, so wait for its effect rather than for idle.
    private fun waitFor(condition: () -> Boolean) = compose.waitUntil(TIMEOUT_MS, condition)

    private fun show() {
        compose.setContent {
            KeepAndroidTheme {
                PinPromptDialog(
                    title = "Confirm",
                    message = "Enter your PIN",
                    confirmLabel = CONFIRM,
                    onVerify = {
                        verifyCalls.incrementAndGet()
                        verdict.await()
                    },
                    onDismiss = { dismissCalls.incrementAndGet() },
                )
            }
        }
        compose.onNode(hasSetTextAction()).performTextInput("1234")
    }

    @Test
    fun twoClicksBeforeARecomposeVerifyOnce() {
        show()
        val click = compose.onNodeWithText(CONFIRM).fetchSemanticsNode().config[SemanticsActions.OnClick].action!!
        compose.runOnUiThread {
            click()
            click()
        }
        compose.runOnIdle { assertEquals(1, verifyCalls.get()) }
        verdict.complete(true)
        waitFor { dismissCalls.get() >= 1 }
        compose.runOnIdle {
            assertEquals(1, dismissCalls.get())
            assertEquals(1, verifyCalls.get())
        }
    }

    @Test
    fun confirmIsDisabledWhileVerifyingAndReturnsAfterAWrongPin() {
        show()
        compose.onNodeWithText(CONFIRM).performClick()
        compose.onNodeWithText(CONFIRM).assertIsNotEnabled()
        verdict.complete(false)
        compose.runOnIdle {
            assertEquals(1, verifyCalls.get())
            assertEquals(0, dismissCalls.get())
        }
        compose.onNode(hasSetTextAction()).performTextInput("5678")
        compose.onNodeWithText(CONFIRM).assertIsEnabled()
    }

    @Test
    fun theDialogCannotBeDismissedWhileVerifying() {
        show()
        compose.onNodeWithText(CONFIRM).performClick()
        compose.onNodeWithText(cancel).assertIsNotEnabled()
        Espresso.closeSoftKeyboard()
        Espresso.pressBack()
        compose.runOnIdle { assertEquals(0, dismissCalls.get()) }
        verdict.complete(true)
        waitFor { dismissCalls.get() >= 1 }
        compose.runOnIdle { assertEquals(1, dismissCalls.get()) }
    }

    @Test
    fun theSettingsDisablePinDialogDisablesOnceOnADoubleClick() {
        compose.setContent {
            KeepAndroidTheme {
                PinSettingsCard(
                    enabled = true,
                    onSetupPin = {},
                    onDisablePin = {
                        verifyCalls.incrementAndGet()
                        verdict.await()
                    },
                )
            }
        }
        val disable = context.getString(R.string.settings_pin_disable)
        compose.onNodeWithText(disable).performClick()
        compose.onNodeWithText(context.getString(R.string.settings_pin_disable_dialog_title)).assertExists()
        compose.onNode(hasSetTextAction()).performTextInput("1234")
        val click = compose.onNode(hasText(disable) and hasAnyAncestor(isDialog())).fetchSemanticsNode().config[SemanticsActions.OnClick].action!!
        compose.runOnUiThread {
            click()
            click()
        }
        waitFor { verifyCalls.get() >= 1 }
        verdict.complete(true)
        val title = context.getString(R.string.settings_pin_disable_dialog_title)
        waitFor { compose.onAllNodesWithText(title).fetchSemanticsNodes().isEmpty() }
        assertEquals(1, verifyCalls.get())
    }

    private companion object {
        const val CONFIRM = "Verify"
        const val TIMEOUT_MS = 5_000L
    }
}
