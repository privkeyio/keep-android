package io.privkey.keep.nip55

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * The audit append's wait, on a single-thread scope like the provider's and a lock
 * like the audit writer's: an append still waiting when the budget expires is
 * refused and must then write nothing, or its row lands for a response that was
 * never returned.
 */
class AwaitWithinTest {

    private val scope = CoroutineScope(Dispatchers.IO.limitedParallelism(1) + SupervisorJob())
    private val lock = Mutex()
    private val wrote = AtomicBoolean(false)
    private val late = AtomicInteger(0)
    private val onLate = { late.incrementAndGet(); Unit }

    @After
    fun stop() = scope.cancel()

    private fun drain() = runBlocking { scope.async { }.await() }

    // The writer's shape: wait for the lock, then ask for the claim before writing.
    private suspend fun write(claim: () -> Boolean): Boolean? = lock.withLock {
        if (!claim()) return@withLock null
        wrote.set(true)
        true
    }

    @Test
    fun aBlockThatFinishesInTimeReturnsItsResult() {
        assertEquals(true, awaitWithin(scope, 1_000, onLate) { claim -> write(claim) })
        assertTrue(wrote.get())
        assertEquals("a block that answered in time is not late", 0, late.get())
    }

    @Test
    fun aBlockQueuedBehindABlockedThreadNeverWrites() {
        val stall = CountDownLatch(1)
        scope.launch { stall.await() }

        assertNull(awaitWithin(scope, 100, onLate) { claim -> write(claim) })

        stall.countDown()
        drain()
        assertFalse(wrote.get())
        assertEquals("a fenced block is not late", 0, late.get())
    }

    // A stalled append that suspends while holding the lock, as one inside a Room
    // transaction does, frees the scope's thread, so the next one starts and waits
    // on the lock. It must still write nothing once its caller has given up.
    @Test
    fun aBlockWaitingOnTheLockPastTheBudgetNeverWrites() {
        val holding = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        scope.launch { lock.withLock { holding.complete(Unit); release.await() } }
        runBlocking { holding.await() }

        assertNull(awaitWithin(scope, 100) { claim -> write(claim) })

        release.complete(Unit)
        drain()
        runBlocking { lock.withLock { } }
        assertFalse(wrote.get())
    }

    @Test
    fun aBlockQueuedWhenTheWaitIsInterruptedNeverWrites() {
        val stall = CountDownLatch(1)
        scope.launch { stall.await() }

        Thread.currentThread().interrupt()
        assertThrows(InterruptedException::class.java) { awaitWithin(scope, 1_000) { claim -> write(claim) } }
        Thread.interrupted()

        stall.countDown()
        drain()
        assertFalse(wrote.get())
    }

    @Test
    fun aBlockPastItsClaimAtTheBudgetIsLeftToFinish() {
        val claimed = CountDownLatch(1)
        val release = CountDownLatch(1)
        val finished = AtomicBoolean(false)

        assertNull(
            awaitWithin(scope, 1_000, onLate) { claim ->
                if (!claim()) return@awaitWithin null
                claimed.countDown()
                release.await()
                finished.set(true)
                true
            }
        )

        assertEquals("the block must have claimed within the budget", 0, claimed.count)
        assertEquals("a block past its claim at the budget is late", 1, late.get())
        release.countDown()
        drain()
        assertTrue(finished.get())
    }

    // A block that claimed and then failed is late too, since its caller cannot tell
    // whether its effect landed. For the audit append that can cost an abandoned row
    // naming no approval, which counts for nothing.
    @Test
    fun aBlockThatClaimedAndThenThrewIsLate() {
        assertThrows(IllegalStateException::class.java) {
            awaitWithin<Boolean>(scope, 1_000, onLate) { claim ->
                check(!claim()) { "failed after its claim" }
                true
            }
        }
        assertEquals(1, late.get())
    }

    @Test
    fun theQueueKeepsServingAfterAFencedBlock() {
        val stall = CountDownLatch(1)
        scope.launch { stall.await() }
        assertNull(awaitWithin(scope, 100) { claim -> write(claim) })
        stall.countDown()

        assertEquals(true, awaitWithin(scope, 1_000) { claim -> write(claim) })
    }
}
