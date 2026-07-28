package io.privkey.keep

import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.storage.SignPolicySelectionPrefs
import io.privkey.keep.storage.toSignPolicy
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.SignPolicyStore
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
 *
 * The screen scrolls, so every interaction scrolls its target into view first.
 * Each test also asserts the tap landed, otherwise a no-op click would satisfy
 * the "nothing was persisted" assertions vacuously.
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
        clearPrefs()
        signPolicyStore = SignPolicyStore(SignPolicySelectionPrefs(context))
    }

    @After
    fun teardown() {
        clearPrefs()
    }

    private fun clearPrefs() {
        context.deleteSharedPreferences(SIGN_POLICY_PREFS)
        context.deleteSharedPreferences(SIGN_POLICY_SELECTION_PREFS)
    }

    private fun setContent(onDone: (SignPolicy) -> Unit) {
        compose.setContent {
            KeepAndroidTheme {
                OnboardingScreen(signPolicyStore, onDone = onDone)
            }
        }
        compose.waitForIdle()
    }

    /**
     * The selectable card for the option titled exactly [title]. `Modifier.selectable`
     * merges its descendants, so the card node carries the title and description text
     * itself; [hasText] matches a whole entry, so the title never matches the body copy.
     */
    private fun optionCard(title: String) =
        compose.onNode(isSelectable() and hasText(title))

    private fun selectAuto() {
        val auto = optionCard(context.getString(R.string.sign_policy_auto))
        auto.performScrollTo().performClick()
        compose.waitForIdle()
        auto.assertIsSelected()
    }

    @Test
    fun selectingPolicyDoesNotPersistIt() {
        var reported: SignPolicy? = null
        setContent { reported = it }

        selectAuto()

        assertEquals(SignPolicy.MANUAL, signPolicyStore.globalPolicy().toSignPolicy())
        assertNull(reported)
    }

    @Test
    fun confirmingReportsSelectionWithoutWritingFromTheScreen() {
        var reported: SignPolicy? = null
        setContent { reported = it }

        selectAuto()
        compose.onNodeWithText(context.getString(R.string.onboarding_get_started))
            .performScrollTo()
            .performClick()
        compose.waitForIdle()

        assertEquals(SignPolicy.AUTO, reported)
        // The screen reports the choice; MainActivity performs the single write.
        assertEquals(SignPolicy.MANUAL, signPolicyStore.globalPolicy().toSignPolicy())
    }

    private companion object {
        const val SIGN_POLICY_PREFS = "keep_sign_policy"
        const val SIGN_POLICY_SELECTION_PREFS = "keep_sign_policy_selection"
    }
}
