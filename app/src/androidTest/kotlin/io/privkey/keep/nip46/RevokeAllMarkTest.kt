package io.privkey.keep.nip46

import android.content.Context
import android.content.SharedPreferences
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RevokeAllMarkTest {
    private lateinit var prefs: SharedPreferences

    @Before
    fun setUp() {
        prefs = InstrumentationRegistry.getInstrumentation().targetContext
            .getSharedPreferences("revoke_all_mark_test", Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
    }

    @After
    fun tearDown() {
        prefs.edit().clear().commit()
    }

    @Test
    fun aSavedMarkOutlivesTheProcess() {
        RevokeAllMark(prefs).set()
        assertTrue(RevokeAllMark(prefs).isSet())
    }

    @Test
    fun aMarkThatWasNotSavedStillAppliesInThisProcess() {
        val mark = RevokeAllMark(prefs)
        mark.set()
        prefs.edit().remove(BunkerService.KEY_REVOKE_ALL_ON_START).commit()
        assertTrue(mark.isSet())
        assertFalse(RevokeAllMark(prefs).isSet())
    }

    @Test
    fun aStartDoesNotClearAMarkSetAfterItLooked() {
        val mark = RevokeAllMark(prefs)
        mark.set()
        val seen = mark.requestsSoFar()
        mark.set()
        assertFalse(mark.clearIfUnchanged(seen) { true })
        assertTrue(mark.isSet())
        assertTrue(RevokeAllMark(prefs).isSet())
    }

    @Test
    fun aStartThatStoppedServingDoesNotClearTheMark() {
        val mark = RevokeAllMark(prefs)
        mark.set()
        assertFalse(mark.clearIfUnchanged(mark.requestsSoFar()) { false })
        assertTrue(mark.isSet())
    }

    @Test
    fun aServingStartClearsTheMarkEverywhere() {
        val mark = RevokeAllMark(prefs)
        mark.set()
        assertTrue(mark.clearIfUnchanged(mark.requestsSoFar()) { true })
        assertFalse(mark.isSet())
        assertFalse(RevokeAllMark(prefs).isSet())
    }

    @Test
    fun aMarkSetAheadIsSavedBeforeTheChange() {
        RevokeAllMark(prefs).setAhead()
        assertTrue(RevokeAllMark(prefs).isSet())
    }

    @Test
    fun aMarkSetAheadOfAChangeThatDidNotHappenIsWithdrawn() {
        val mark = RevokeAllMark(prefs)
        checkNotNull(mark.setAhead()).invoke()
        assertFalse(mark.isSet())
        assertFalse(RevokeAllMark(prefs).isSet())
    }

    @Test
    fun aWithdrawLeavesAMarkThatWasAlreadyPending() {
        val mark = RevokeAllMark(prefs)
        mark.set()
        assertNull(mark.setAhead())
        assertTrue(mark.isSet())
    }

    @Test
    fun aWithdrawLeavesAMarkSetAgainAfterIt() {
        val mark = RevokeAllMark(prefs)
        val withdraw = checkNotNull(mark.setAhead())
        mark.set()
        withdraw()
        assertTrue(mark.isSet())
        assertTrue(RevokeAllMark(prefs).isSet())
    }
}
