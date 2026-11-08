package io.privkey.keep

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.ui.theme.KeepAndroidTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CreateGroupReviewTest {

    // createComposeRule() is deprecated in favor of the v2 API; the classic rule
    // is intentional here, and the project builds with -Werror.
    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun beginIsRefusedForANameJoinersWouldReject() {
        compose.setContent {
            KeepAndroidTheme {
                CreateGroupScreen(
                    relays = listOf("wss://relay.example"),
                    onCreateGroup = { _, _, _ -> },
                    onDkgBegin = { "a".repeat(64) },
                    onCancel = {},
                    onGetCipher = { error("not reached") },
                    onBiometricAuth = { _, _ -> },
                    onDismiss = {},
                    createGroupState = CreateGroupState.Idle,
                )
            }
        }
        val name = compose.onNodeWithText(context.getString(R.string.create_group_name_label))
        val begin = compose.onNodeWithText(context.getString(R.string.create_group_begin))

        begin.assertIsEnabled()
        name.performTextClearance()
        begin.assertIsNotEnabled()
        name.performTextInput("Fam\u200Bily")
        begin.assertIsNotEnabled()
        compose.onNodeWithText(context.getString(R.string.create_group_name_invalid)).assertIsDisplayed()
        name.performTextClearance()
        name.performTextInput("Family ")
        begin.assertIsEnabled()
        compose.onNodeWithText(context.getString(R.string.create_group_name_invalid)).assertDoesNotExist()
    }

    @Test
    fun theReviewShowsTheGroupNameAndRelays() {
        val roster = RosterPayload(
            name = "Family vault",
            threshold = 2,
            participants = 3,
            relays = listOf("wss://one.example", "wss://two.example"),
            roster = (1..3).map { RosterEntry(it, it.toString().repeat(64)) },
        )
        compose.setContent {
            KeepAndroidTheme {
                RosterReview(roster, ourIndex = 2, fingerprint = "AB12 EF00 9C34 7D5E", confirmed = false) {}
            }
        }

        compose.onNodeWithText(context.getString(R.string.create_group_name_label)).assertIsDisplayed()
        compose.onNodeWithText("Family vault").assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.create_group_review_relays_label)).assertIsDisplayed()
        compose.onNodeWithText("wss://one.example").assertIsDisplayed()
        compose.onNodeWithText("wss://two.example").assertIsDisplayed()
    }
}
