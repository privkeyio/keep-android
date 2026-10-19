package io.privkey.keep

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LiveNodeTrackerTest {

    @Test
    fun nothingIsLiveBeforeTheFirstInitialize() {
        assertFalse(LiveNodeTracker().isLive())
    }

    @Test
    fun anInitializeThatSucceededIsLive() {
        val tracker = LiveNodeTracker()
        tracker.built(tracker.beginInit())
        assertTrue(tracker.isLive())
    }

    @Test
    fun aDropEndsIt() {
        val tracker = LiveNodeTracker()
        tracker.built(tracker.beginInit())
        tracker.dropped()
        assertFalse(tracker.isLive())
    }

    @Test
    fun anInitializeAfterTheDropIsLiveAgain() {
        val tracker = LiveNodeTracker()
        tracker.built(tracker.beginInit())
        tracker.dropped()
        tracker.built(tracker.beginInit())
        assertTrue(tracker.isLive())
    }

    // The case a flag cleared at the end of an initialize would get wrong: the drop lands
    // while the initialize is running, so the node it reports may be the dropped one.
    @Test
    fun anInitializeADropOverlappedIsNotLive() {
        val tracker = LiveNodeTracker()
        val startedAt = tracker.beginInit()
        tracker.dropped()
        tracker.built(startedAt)
        assertFalse(tracker.isLive())
    }
}
