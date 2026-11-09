package io.privkey.keep

import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
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
    private var verifyCalls = 0
    private var dismissCalls = 0

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
        compose.runOnIdle { assertEquals(1, dismissCalls) }
    }

    @Test
    fun confirmIsDisabledWhileVerifying() {
        show()
        compose.onNodeWithText(CONFIRM).performClick()
        compose.onNodeWithText(CONFIRM).assertIsNotEnabled()
        verdict.complete(false)
        compose.runOnIdle {
            assertEquals(1, verifyCalls)
            assertEquals(0, dismissCalls)
        }
    }

    private companion object {
        const val CONFIRM = "Verify"
    }
}
