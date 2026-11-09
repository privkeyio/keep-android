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
    @Volatile private var verifyCalls = 0
    @Volatile private var dismissCalls = 0
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
                        verifyCalls++
                        verdict.await()
                    },
                    onDismiss = { dismissCalls++ },
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
        compose.runOnIdle { assertEquals(1, verifyCalls) }
        verdict.complete(true)
        waitFor { dismissCalls == 1 }
        assertEquals(1, verifyCalls)
    }

    @Test
    fun confirmIsDisabledWhileVerifyingAndReturnsAfterAWrongPin() {
        show()
        compose.onNodeWithText(CONFIRM).performClick()
        compose.onNodeWithText(CONFIRM).assertIsNotEnabled()
        verdict.complete(false)
        compose.runOnIdle {
            assertEquals(1, verifyCalls)
            assertEquals(0, dismissCalls)
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
        compose.runOnIdle { assertEquals(0, dismissCalls) }
        verdict.complete(true)
        waitFor { dismissCalls == 1 }
    }

    @Test
    fun theSettingsDisablePinDialogDisablesOnceOnADoubleClick() {
        compose.setContent {
            KeepAndroidTheme {
                PinSettingsCard(
                    enabled = true,
                    onSetupPin = {},
                    onDisablePin = {
                        verifyCalls++
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
        waitFor { verifyCalls >= 1 }
        verdict.complete(true)
        val title = context.getString(R.string.settings_pin_disable_dialog_title)
        waitFor { compose.onAllNodesWithText(title).fetchSemanticsNodes().isEmpty() }
        assertEquals(1, verifyCalls)
    }

    private companion object {
        const val CONFIRM = "Verify"
        const val TIMEOUT_MS = 5_000L
    }
}
