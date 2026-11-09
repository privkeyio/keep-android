package io.privkey.keep

import android.view.WindowManager
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.espresso.Espresso
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isRoot
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.ui.theme.KeepAndroidTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PendingDkgShareDialogTest {

    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private var later = 0
    private var recover = 0
    private var discard = 0

    private fun show() = compose.setContent {
        KeepAndroidTheme {
            PendingDkgShareDialog(
                groupName = "Family Wallet",
                onLater = { later++ },
                onRecover = { recover++ },
                onDiscard = { discard++ },
            )
        }
    }

    @Test
    fun laterDefersWithoutRecoveringOrDiscarding() {
        show()
        compose.onNodeWithText(context.getString(R.string.main_pending_dkg_later)).performClick()
        compose.runOnIdle {
            assertEquals(1, later)
            assertEquals(0, recover)
            assertEquals(0, discard)
        }
    }

    @Test
    fun backDefersWithoutDiscarding() {
        show()
        compose.waitForIdle()
        Espresso.pressBack()
        compose.runOnIdle {
            assertEquals(1, later)
            assertEquals(0, discard)
        }
    }

    @Test
    fun theDialogWindowIsSecure() {
        show()
        compose.waitForIdle()
        var flags = 0
        onView(isRoot()).inRoot(isDialog()).check { view, _ ->
            flags = (view.rootView.layoutParams as WindowManager.LayoutParams).flags
        }
        assertTrue(flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
    }
}
