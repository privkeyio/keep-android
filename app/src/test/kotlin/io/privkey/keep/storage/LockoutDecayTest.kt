package io.privkey.keep.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class LockoutDecayTest {

    private val day = 86_400_000L
    private val wall = 1_800_000_000_000L
    private val realtime = 5_000_000L

    private fun decay(level: Int = 3, anchorRealtime: Long = realtime, nowWall: Long, nowRealtime: Long) =
        decayLockoutLevel(level, wall, anchorRealtime, nowWall, nowRealtime, day)

    @Test
    fun lessThanADayChangesNothing() {
        assertNull(decay(nowWall = wall + day - 1, nowRealtime = realtime + day - 1))
    }

    @Test
    fun aDayOnBothClocksDropsOneLevelAndKeepsTheRemainder() {
        assertEquals(
            LockoutDecay(2, wall + day, realtime + day),
            decay(nowWall = wall + day + 7, nowRealtime = realtime + day + 7)
        )
    }

    @Test
    fun aWallClockSetForwardDoesNotDecay() {
        assertNull(decay(nowWall = wall + 10 * day, nowRealtime = realtime + 60_000))
    }

    @Test
    fun aWallClockSetBackRestartsTheWindowWithoutLoweringTheLevel() {
        assertEquals(
            LockoutDecay(3, wall - 1, realtime + day * 2),
            decay(nowWall = wall - 1, nowRealtime = realtime + day * 2)
        )
    }

    @Test
    fun afterARebootOnlyTheUptimeCounts() {
        val uptime = day + 5
        assertEquals(
            LockoutDecay(2, wall + 3 * day - 5, uptime - 5),
            decay(anchorRealtime = 10 * day, nowWall = wall + 3 * day, nowRealtime = uptime)
        )
    }

    @Test
    fun aRebootWithShortUptimeReanchorsWithoutLoweringTheLevel() {
        assertEquals(
            LockoutDecay(3, wall + 3 * day - 1_000, 0),
            decay(nowWall = wall + 3 * day, nowRealtime = 1_000)
        )
    }

    @Test
    fun uptimeBeforeTheFirstCheckAfterARebootStillCounts() {
        val reanchored = decay(nowWall = wall + 3 * day, nowRealtime = 1_000)!!
        assertEquals(
            LockoutDecay(2, reanchored.anchorWall + day, day),
            decayLockoutLevel(3, reanchored.anchorWall, reanchored.anchorRealtime, reanchored.anchorWall + day + 1_000, day + 1_000, day)
        )
    }

    @Test
    fun aMissingMonotonicAnchorRestartsTheWindow() {
        assertEquals(
            LockoutDecay(3, wall + 10 * day, realtime),
            decay(anchorRealtime = -1, nowWall = wall + 10 * day, nowRealtime = realtime)
        )
    }

    @Test
    fun manyDaysStopAtLevelZero() {
        assertEquals(0, decay(nowWall = wall + 30 * day, nowRealtime = realtime + 30 * day)!!.level)
    }
}
