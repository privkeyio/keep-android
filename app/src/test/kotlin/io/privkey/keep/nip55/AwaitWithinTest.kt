package io.privkey.keep.nip55

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The audit append's wait, on a single-thread scope like the provider's: an append
 * queued behind a stalled one is refused at the budget and must then never run, or
 * its row lands for a response that was never returned.
 */
class AwaitWithinTest {

    private val scope = CoroutineScope(Dispatchers.IO.limitedParallelism(1) + SupervisorJob())

    @After
    fun stop() = scope.cancel()

    private fun drain() = runBlocking { scope.async { }.await() }

    @Test
    fun aBlockThatFinishesInTimeReturnsItsResult() {
        assertEquals(true, awaitWithin(scope, 1_000) { true })
    }

    @Test
    fun aBlockQueuedPastTheBudgetNeverRuns() {
        val stall = CountDownLatch(1)
        scope.launch { stall.await() }
        val ran = AtomicBoolean(false)

        assertNull(awaitWithin(scope, 100) { ran.set(true); true })

        stall.countDown()
        drain()
        assertFalse(ran.get())
    }

    @Test
    fun aBlockAlreadyRunningAtTheBudgetIsLeftToFinish() {
        val release = CountDownLatch(1)
        val finished = AtomicBoolean(false)

        assertNull(awaitWithin(scope, 100) { release.await(); finished.set(true); true })

        release.countDown()
        drain()
        assertTrue(finished.get())
    }

    @Test
    fun theQueueKeepsServingAfterAFencedBlock() {
        val stall = CountDownLatch(1)
        scope.launch { stall.await() }
        assertNull(awaitWithin(scope, 100) { true })
        stall.countDown()

        assertEquals(true, awaitWithin(scope, 1_000) { true })
    }
}
