package io.privkey.keep.nip55

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The provider's wait on the handler: a result is either returned to a caller still
 * waiting or handed to the late path, never both and never neither, since a
 * signature that reached neither would exist with no record of it.
 */
class AwaitOrHandOffTest {

    private val scope = CoroutineScope(Dispatchers.IO.limitedParallelism(2) + SupervisorJob())
    private val late = CopyOnWriteArrayList<String>()
    private val lateDone = CountDownLatch(1)
    private val onLate = { result: String -> late += result; lateDone.countDown() }

    @After
    fun stop() = scope.cancel()

    @Test
    fun aResultInTimeIsReturnedAndNotHandedOn() {
        assertEquals("sig", awaitOrHandOff(scope, 1_000, onLate) { "sig" })
        assertTrue(late.isEmpty())
    }

    @Test
    fun aResultAfterTheWaitGaveUpIsHandedOnOnce() {
        val release = CountDownLatch(1)
        assertNull(awaitOrHandOff(scope, 50, onLate) { release.await(); "sig" })

        release.countDown()
        assertTrue(lateDone.await(5, TimeUnit.SECONDS))
        assertEquals(listOf("sig"), late)
    }

    @Test
    fun aFailureInTimeReachesTheCaller() {
        assertThrows(IllegalStateException::class.java) {
            awaitOrHandOff<String>(scope, 1_000, onLate) { error("no co-signer") }
        }
        assertTrue(late.isEmpty())
    }

    @Test
    fun aFailureAfterTheWaitGaveUpHandsNothingOn() {
        val release = CountDownLatch(1)
        val finished = CountDownLatch(1)
        assertNull(
            awaitOrHandOff<String>(scope, 50, onLate) {
                try {
                    release.await()
                    error("no co-signer")
                } finally {
                    finished.countDown()
                }
            }
        )

        release.countDown()
        assertTrue(finished.await(5, TimeUnit.SECONDS))
        Thread.sleep(100)
        assertTrue(late.isEmpty())
    }

    @Test
    fun aResultWhileTheCallerIsInterruptedIsHandedOn() {
        val release = CountDownLatch(1)
        Thread.currentThread().interrupt()
        try {
            assertThrows(InterruptedException::class.java) {
                awaitOrHandOff(scope, 1_000, onLate) { release.await(); "sig" }
            }
        } finally {
            Thread.interrupted()
        }

        release.countDown()
        assertTrue(lateDone.await(5, TimeUnit.SECONDS))
        assertEquals(listOf("sig"), late)
    }
}
