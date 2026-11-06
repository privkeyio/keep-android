package io.privkey.keep

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.ui.theme.KeepAndroidTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class UnreadableSharesCardTest {

    // createComposeRule() is deprecated in favor of the v2 API; the classic rule
    // is intentional here, and the project builds with -Werror.
    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val group = "a".repeat(32) + "b".repeat(32)

    @Test
    fun removeIsOfferedOnlyAfterARetryFails() {
        var failed by mutableStateOf(emptySet<String>())
        var retries = 0
        var removed: String? = null
        compose.setContent {
            KeepAndroidTheme {
                UnreadableSharesCard(
                    groups = listOf(group),
                    retryFailed = failed,
                    retrying = false,
                    onRetry = { retries++; failed = setOf(group) },
                    onRemove = { removed = it },
                )
            }
        }

        compose.onNodeWithText(shortGroup(group)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.share_unreadable_retry_first)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.share_unreadable_remove)).assertDoesNotExist()

        compose.onNodeWithText(context.getString(R.string.share_unreadable_retry)).performClick()
        compose.onNodeWithText(context.getString(R.string.share_unreadable_retry_first)).assertDoesNotExist()
        compose.onNodeWithText(context.getString(R.string.share_unreadable_remove)).performClick()

        assertEquals(1, retries)
        assertEquals(group, removed)
    }

    @Test
    fun buttonsAreDisabledWhileARetryRuns() {
        compose.setContent {
            KeepAndroidTheme {
                UnreadableSharesCard(
                    groups = listOf(group),
                    retryFailed = setOf(group),
                    retrying = true,
                    onRetry = {},
                    onRemove = {},
                )
            }
        }

        compose.onNodeWithText(context.getString(R.string.share_unreadable_retry)).assertIsNotEnabled()
        compose.onNodeWithText(context.getString(R.string.share_unreadable_remove)).assertIsNotEnabled()
    }

    @Test
    fun keepItDismissesWithoutRemoving() {
        var confirmed = false
        var dismissed = false
        compose.setContent {
            KeepAndroidTheme {
                RemoveUnreadableShareDialog(group, onConfirm = { confirmed = true }, onDismiss = { dismissed = true })
            }
        }

        compose.onNodeWithText(context.getString(R.string.share_unreadable_remove_text, shortGroup(group))).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.share_unreadable_keep)).performClick()

        assertEquals(true, dismissed)
        assertEquals(false, confirmed)
    }

    @Test
    fun aSetAsideShareCanBePutBackOrDiscarded() {
        var restored: String? = null
        var discarded: String? = null
        compose.setContent {
            KeepAndroidTheme {
                SetAsideSharesCard(
                    groups = listOf(group),
                    busy = false,
                    onRestore = { restored = it },
                    onDiscard = { discarded = it },
                )
            }
        }

        compose.onNodeWithText(shortGroup(group)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.share_set_aside_restore)).performClick()
        compose.onNodeWithText(context.getString(R.string.share_set_aside_discard)).performClick()

        assertEquals(group, restored)
        assertEquals(group, discarded)
    }

    @Test
    fun setAsideButtonsAreDisabledWhileAChangeRuns() {
        compose.setContent {
            KeepAndroidTheme {
                SetAsideSharesCard(groups = listOf(group), busy = true, onRestore = {}, onDiscard = {})
            }
        }

        compose.onNodeWithText(context.getString(R.string.share_set_aside_restore)).assertIsNotEnabled()
        compose.onNodeWithText(context.getString(R.string.share_set_aside_discard)).assertIsNotEnabled()
    }

    @Test
    fun theDiscardDialogNamesTheAccountAndCanBeDismissed() {
        var confirmed = false
        var dismissed = false
        compose.setContent {
            KeepAndroidTheme {
                DiscardSetAsideShareDialog(group, onConfirm = { confirmed = true }, onDismiss = { dismissed = true })
            }
        }

        compose.onNodeWithText(context.getString(R.string.share_set_aside_discard_text, shortGroup(group))).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.share_unreadable_keep)).performClick()

        assertEquals(true, dismissed)
        assertEquals(false, confirmed)
    }
}
