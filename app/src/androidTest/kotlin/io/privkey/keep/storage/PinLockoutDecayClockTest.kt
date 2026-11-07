package io.privkey.keep.storage

import android.content.Context
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

// The lockout level must not decay because the wall clock moved: setting the date back
// used to reset it to 0, and a stale wall anchor counted days the device never lived.
@RunWith(AndroidJUnit4::class)
class PinLockoutDecayClockTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private val day = 86_400_000L

    @Before
    fun setup() {
        context.deleteSharedPreferences(PinStore.PREFS_NAME)
        assertTrue(PinStore(context).setPin("482916"))
    }

    @After
    fun teardown() {
        context.deleteSharedPreferences(PinStore.PREFS_NAME)
    }

    private fun stage(level: Int, anchorWall: Long, anchorRealtime: Long?) {
        val editor = KeystoreEncryptedPrefs.create(context, PinStore.PREFS_NAME).edit()
            .putInt("lockout_level", level)
            .putLong("last_lockout_cleared", anchorWall)
        if (anchorRealtime != null) editor.putLong("last_lockout_cleared_realtime", anchorRealtime) else editor.remove("last_lockout_cleared_realtime")
        assertTrue(editor.commit())
    }

    private fun stored() = KeystoreEncryptedPrefs.create(context, PinStore.PREFS_NAME)

    @Test
    fun aWallClockSetBackKeepsTheLevel() {
        stage(level = 3, anchorWall = System.currentTimeMillis() + 3_600_000L, anchorRealtime = SystemClock.elapsedRealtime())
        val wallBefore = System.currentTimeMillis()
        val realtimeBefore = SystemClock.elapsedRealtime()

        assertEquals(0L, PinStore(context).getLockoutRemainingMs())

        val wallAfter = System.currentTimeMillis()
        val realtimeAfter = SystemClock.elapsedRealtime()
        val prefs = stored()
        assertEquals(3, prefs.getInt("lockout_level", -1))
        val wallAnchor = prefs.getLong("last_lockout_cleared", -1)
        assertTrue("wall anchor $wallAnchor not in [$wallBefore, $wallAfter]", wallAnchor in wallBefore..wallAfter)
        val realtimeAnchor = prefs.getLong("last_lockout_cleared_realtime", -1)
        assertTrue("anchor $realtimeAnchor not in [$realtimeBefore, $realtimeAfter]", realtimeAnchor in realtimeBefore..realtimeAfter)
    }

    @Test
    fun daysOnTheWallClockAloneDoNotDecay() {
        stage(level = 3, anchorWall = System.currentTimeMillis() - 10 * day, anchorRealtime = SystemClock.elapsedRealtime())

        assertEquals(0L, PinStore(context).getLockoutRemainingMs())

        assertEquals(3, stored().getInt("lockout_level", -1))
    }

    @Test
    fun aRecordWithoutAMonotonicAnchorIsReanchoredAtTheSameLevel() {
        stage(level = 3, anchorWall = System.currentTimeMillis() - 10 * day, anchorRealtime = null)
        val before = SystemClock.elapsedRealtime()

        assertEquals(0L, PinStore(context).getLockoutRemainingMs())

        val after = SystemClock.elapsedRealtime()
        val prefs = stored()
        assertEquals(3, prefs.getInt("lockout_level", -1))
        val anchor = prefs.getLong("last_lockout_cleared_realtime", -1)
        assertTrue("anchor $anchor not in [$before, $after]", anchor in before..after)
    }
}
