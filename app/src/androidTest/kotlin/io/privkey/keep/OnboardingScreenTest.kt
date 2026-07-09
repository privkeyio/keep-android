package io.privkey.keep

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.storage.SignPolicyStore
import io.privkey.keep.ui.theme.KeepAndroidTheme
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Onboarding hoists persistence to its caller: selecting an option only moves the
 * selection, and the chosen policy is reported once via `onDone`. This guards the
 * regression where tapping an option immediately committed the global signing
 * policy, so merely reading the least-secure "Auto" option applied it.
 */
@RunWith(AndroidJUnit4::class)
class OnboardingScreenTest {

    // createComposeRule() is deprecated in favor of the v2 API; the classic rule
    // is intentional here, and the project builds with -Werror.
    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var signPolicyStore: SignPolicyStore

    @Before
    fun setup() {
        context.deleteSharedPreferences(SIGN_POLICY_PREFS)
        signPolicyStore = SignPolicyStore(context)
    }

    @After
    fun teardown() {
        context.deleteSharedPreferences(SIGN_POLICY_PREFS)
    }

    @Test
    fun selectingPolicyDoesNotPersistIt() {
        var reported: SignPolicy? = null
        compose.setContent {
            KeepAndroidTheme {
                OnboardingScreen(signPolicyStore, onDone = { reported = it })
            }
        }
        compose.waitForIdle()

        compose.onNodeWithText(context.getString(R.string.sign_policy_auto)).performClick()
        compose.waitForIdle()

        assertEquals(SignPolicy.MANUAL, signPolicyStore.getGlobalPolicy())
        assertNull(reported)
    }

    @Test
    fun confirmingReportsSelectionWithoutWritingFromTheScreen() {
        var reported: SignPolicy? = null
        compose.setContent {
            KeepAndroidTheme {
                OnboardingScreen(signPolicyStore, onDone = { reported = it })
            }
        }
        compose.waitForIdle()

        compose.onNodeWithText(context.getString(R.string.sign_policy_auto)).performClick()
        compose.onNodeWithText(context.getString(R.string.onboarding_get_started)).performClick()
        compose.waitForIdle()

        assertEquals(SignPolicy.AUTO, reported)
        // The screen reports the choice; MainActivity performs the single write.
        assertEquals(SignPolicy.MANUAL, signPolicyStore.getGlobalPolicy())
    }

    private companion object {
        const val SIGN_POLICY_PREFS = "keep_sign_policy"
    }
}
