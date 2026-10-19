package io.privkey.keep

import androidx.compose.runtime.remember
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.storage.KeystoreEncryptedPrefs
import io.privkey.keep.storage.PinRecord
import io.privkey.keep.storage.PinStore
import io.privkey.keep.storage.breakNameResolution
import io.privkey.keep.storage.corruptStoredValue
import io.privkey.keep.storage.forgetWriteProbe
import io.privkey.keep.storage.writeAndFindStoredName
import io.privkey.keep.ui.theme.KeepAndroidTheme
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The way out of an unreadable PIN record, which is what makes failing the read closed
 * safe to do at all.
 *
 * With the record unreadable the gate asks, the hash in the same file cannot verify any
 * PIN, and waiting does not help, so without this screen state the person is locked out
 * of an app holding their keys. These assert that the state is reported, that the
 * removal is offered, and that it is not offered for a record that reads fine.
 */
@RunWith(AndroidJUnit4::class)
class PinUnlockScreenUnreadableTest {

    // createComposeRule() is deprecated in favor of the v2 API; the classic rule
    // is intentional here, and the project builds with -Werror.
    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private val unreadableTitle get() = context.getString(R.string.pin_unlock_unreadable_title)
    private val removeLabel get() = context.getString(R.string.pin_unlock_unreadable_remove)

    @Before
    fun setup() {
        clear()
    }

    @After
    fun teardown() {
        clear()
    }

    private fun clear() {
        context.deleteSharedPreferences(PinStore.PREFS_NAME)
    }

    /**
     * [authorizePinRemoval] stands in for whichever factor production asks for. It answers
     * true by default so the cases below assert what the screen does once removal is
     * authorized; the case that refuses it passes false.
     */
    private fun showScreen(
        onBiometricAuth: (suspend () -> Boolean)? = null,
        authorizePinRemoval: suspend () -> Boolean = { true },
        onUnlocked: () -> Unit = {}
    ) {
        compose.setContent {
            // Remembered, not rebuilt per recomposition: production hands this screen one
            // store for the life of the process.
            val store = remember { PinStore(context) }
            KeepAndroidTheme {
                PinUnlockScreen(
                    pinStore = store,
                    onUnlocked = onUnlocked,
                    onBiometricAuth = onBiometricAuth,
                    authorizePinRemoval = authorizePinRemoval
                )
            }
        }
    }

    // A generous bound, since the CI emulator runs these at about half local speed, and
    // waitUntil returns as soon as the condition holds, so it costs nothing on a pass.
    private fun awaitText(text: String) = compose.waitUntil(timeoutMillis = AWAIT_MS) {
        compose.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty()
    }

    @Test
    fun anUnreadableRecordIsReportedAndOffersRemoval() {
        PinStore(context).setPin(GOOD_PIN)
        breakNameResolution(context, PinStore.PREFS_NAME)
        showScreen()

        awaitText(unreadableTitle)
        compose.onNodeWithText(unreadableTitle).assertIsDisplayed()
        compose.onNodeWithText(removeLabel).assertIsDisplayed()
        // Not the lockout state, which an unreadable record also reports and which
        // offers only waiting.
        compose.onNodeWithText(
            context.getString(R.string.pin_unlock_locked_out_title)
        ).assertDoesNotExist()
    }

    // The readable case, so the assertions above cannot pass on a screen that offers
    // removal whatever it reads.
    @Test
    fun aReadablePinOffersNoRemoval() {
        PinStore(context).setPin(GOOD_PIN)
        showScreen()

        awaitText(context.getString(R.string.pin_unlock_button))
        compose.onNodeWithText(unreadableTitle).assertDoesNotExist()
        compose.onNodeWithText(removeLabel).assertDoesNotExist()
    }

    @Test
    fun removingAnUnreadableRecordClearsItAndUnlocks() {
        PinStore(context).setPin(GOOD_PIN)
        breakNameResolution(context, PinStore.PREFS_NAME)
        var unlocked = false
        showScreen(onUnlocked = { unlocked = true })

        awaitText(unreadableTitle)
        compose.onNodeWithText(removeLabel).performClick()

        compose.waitUntil(timeoutMillis = AWAIT_MS) { unlocked }
        assertTrue("removal has to unlock, or the screen has no exit", unlocked)
        assertEquals(PinRecord.NOT_SET, PinStore(context).pinRecord())
        assertFalse(PinStore(context).requiresAuthentication())
    }

    /**
     * Removal takes away an authentication factor before anyone has authenticated, so it
     * waits on whatever the caller gates it with. A refusal must leave the record alone.
     */
    @Test
    fun aRefusedAuthorizationLeavesTheRecordAlone() {
        PinStore(context).setPin(GOOD_PIN)
        breakNameResolution(context, PinStore.PREFS_NAME)
        var unlocked = false
        showScreen(authorizePinRemoval = { false }, onUnlocked = { unlocked = true })

        awaitText(unreadableTitle)
        compose.onNodeWithText(removeLabel).performClick()

        compose.waitForIdle()
        assertFalse("a refused authorization must not remove the PIN", unlocked)
        assertEquals(PinRecord.UNREADABLE, PinStore(context).pinRecord())
    }

    /**
     * No biometric unlock is offered in this state, even with a biometric available.
     *
     * One that left the record alone could not hold: the activity re-derives the unlock
     * from the session on every resume, the session cannot be refreshed against a file
     * that will not decrypt, and dismissing the prompt resumes the activity, so the lock
     * screen would come straight back. Pinned so it is not added back as a convenience.
     */
    @Test
    fun theUnreadableStateOffersNoUnlockThatCannotHold() {
        PinStore(context).setPin(GOOD_PIN)
        breakNameResolution(context, PinStore.PREFS_NAME)
        showScreen(onBiometricAuth = { true })

        awaitText(unreadableTitle)
        compose.onNodeWithText(context.getString(R.string.pin_unlock_use_biometrics))
            .assertDoesNotExist()
        compose.onNodeWithText(removeLabel).assertIsDisplayed()
    }

    /**
     * The record recovers between the screen being drawn and the tap. The clear refuses a
     * record it can read, and before this the screen stayed in this state with a button
     * that would refuse forever. It has to go back to asking for the PIN.
     */
    @Test
    fun aRecordThatRecoversBeforeTheTapReturnsToPinEntry() {
        val storedName = writeAndFindStoredName(context, PinStore.PREFS_NAME) {
            KeystoreEncryptedPrefs.create(context, PinStore.PREFS_NAME)
                .edit().putBoolean("pin_enabled", true).commit()
        }
        corruptStoredValue(context, PinStore.PREFS_NAME, storedName)
        var unlocked = false
        showScreen(onUnlocked = { unlocked = true })
        awaitText(unreadableTitle)

        // Repaired underneath the screen: setPin overwrites the damaged flag and writes a
        // usable hash, so the record now reads SET.
        assertTrue(PinStore(context).setPin(GOOD_PIN))
        compose.onNodeWithText(removeLabel).performClick()

        awaitText(context.getString(R.string.pin_unlock_button))
        compose.onNodeWithText(unreadableTitle).assertDoesNotExist()
        assertFalse("a readable PIN has to be entered, not skipped", unlocked)
        assertEquals("and it was not removed", PinRecord.SET, PinStore(context).pinRecord())
        forgetWriteProbe(context, PinStore.PREFS_NAME)
    }

    /**
     * A single corrupted value rather than the whole file, since that is the other
     * shape the fault takes and the screen must reach the same state for it.
     */
    @Test
    fun aSingleUnreadableValueReachesTheSameState() {
        val storedName = writeAndFindStoredName(context, PinStore.PREFS_NAME) {
            KeystoreEncryptedPrefs.create(context, PinStore.PREFS_NAME)
                .edit().putBoolean("pin_enabled", true).commit()
        }
        corruptStoredValue(context, PinStore.PREFS_NAME, storedName)
        showScreen()

        awaitText(unreadableTitle)
        compose.onNodeWithText(removeLabel).assertIsDisplayed()
        forgetWriteProbe(context, PinStore.PREFS_NAME)
    }

    private companion object {
        const val GOOD_PIN = "4917"
        const val AWAIT_MS = 15_000L
    }
}
