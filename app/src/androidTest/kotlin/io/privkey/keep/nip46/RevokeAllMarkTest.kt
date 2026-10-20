package io.privkey.keep.nip46

import android.content.Context
import android.content.SharedPreferences
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertFalse
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
    fun aStartDuringAnOpenChangeStillRevokes() {
        val mark = RevokeAllMark(prefs)
        mark.setAhead()
        assertTrue(mark.isSet())
    }

    @Test
    fun aChangeThatSwitchedKeepsTheMark() {
        val mark = RevokeAllMark(prefs)
        val seen = mark.requestsSoFar()
        mark.setAhead()(true)
        assertTrue(mark.isSet())
        assertTrue(RevokeAllMark(prefs).isSet())
        assertFalse("a start that looked before the switch must not clear it", mark.clearIfUnchanged(seen) { true })
    }

    @Test
    fun aChangeThatDidNotSwitchWithdrawsTheMark() {
        val mark = RevokeAllMark(prefs)
        mark.setAhead()(false)
        assertFalse(mark.isSet())
        assertFalse(RevokeAllMark(prefs).isSet())
    }

    @Test
    fun aStartKeepsTheSavedMarkWhileAChangeIsOpen() {
        val mark = RevokeAllMark(prefs)
        mark.set()
        val finish = mark.setAhead()
        assertTrue(mark.clearIfUnchanged(mark.requestsSoFar()) { true })
        assertTrue("the open change still needs the saved mark", RevokeAllMark(prefs).isSet())
        finish(true)
        assertTrue(mark.isSet())
        assertTrue(RevokeAllMark(prefs).isSet())
    }

    @Test
    fun aChangeThatDidNotSwitchWithdrawsAMarkAStartAlreadyRevokedFor() {
        val mark = RevokeAllMark(prefs)
        mark.set()
        val finish = mark.setAhead()
        assertTrue(mark.clearIfUnchanged(mark.requestsSoFar()) { true })
        finish(false)
        assertFalse(mark.isSet())
        assertFalse(RevokeAllMark(prefs).isSet())
    }

    @Test
    fun anOpenChangeKeepsTheMarkAnotherOneFinishedWithout() {
        val mark = RevokeAllMark(prefs)
        val first = mark.setAhead()
        mark.setAhead()(false)
        assertTrue(RevokeAllMark(prefs).isSet())
        first(false)
        assertFalse(mark.isSet())
        assertFalse(RevokeAllMark(prefs).isSet())
    }

    @Test
    fun aChangeThatDidNotSwitchLeavesAMarkThatWasAlreadyPending() {
        val mark = RevokeAllMark(prefs)
        mark.set()
        mark.setAhead()(false)
        assertTrue(mark.isSet())
        assertTrue(RevokeAllMark(prefs).isSet())
    }

    @Test
    fun aChangeThatDidNotSwitchLeavesAMarkSavedByAnEarlierProcess() {
        RevokeAllMark(prefs).set()
        val mark = RevokeAllMark(prefs)
        val finish = mark.setAhead()
        assertTrue(mark.isSet())
        finish(false)
        assertTrue(mark.isSet())
        assertTrue(RevokeAllMark(prefs).isSet())
    }
}
