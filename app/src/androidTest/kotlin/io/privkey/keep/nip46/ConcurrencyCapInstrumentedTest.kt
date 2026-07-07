package io.privkey.keep.nip46

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.BunkerApprovalRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Collections
import java.util.UUID
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.atomic.AtomicInteger

/**
 * Anti-DoS coverage for the NIP-46 admission control in
 * [BunkerService.addPendingApproval] (gh #378, split of #323): the per-client
 * MAX_CONCURRENT_PER_CLIENT and the global MAX_PENDING_APPROVALS caps, the
 * decrement-on-respond that frees a slot, and per-client isolation. Authorization
 * (RequestGateTest) and rate-limit (RateLimitBudget/DelegationTest) are covered
 * elsewhere; this only exercises the concurrency-cap seam.
 *
 * Instrumented, not a JVM unit test: the per-client reject branch builds its log
 * message with truncatePubkey() -> the native uniffi truncateStr, so it only runs
 * where libuniffi is loaded. On device that branch executes for real.
 *
 * The companion counters (globalPendingCount, clientPendingCounts, pendingApprovals)
 * are process-global static state. clearRateLimitState() is not used for reset: it
 * leaves pendingApprovals untouched, so state is instead drained in @After through the
 * production remove path (respondToApproval, approved=false — the branch that skips
 * the native limiter's resetConsecutive), which removes each pending approval and
 * returns the global and per-client counters to zero (the per-client map keeps its
 * now-zero entries; a 0 count never trips the cap). Since this is the only instrumented
 * class touching these counters, that @After drain gives full inter-method isolation.
 */
@RunWith(AndroidJUnit4::class)
class ConcurrencyCapInstrumentedTest {

    // Synchronized: concurrentAddsRespectPerClientCap mutates this from many threads.
    private val added = Collections.synchronizedList(mutableListOf<Pair<String, String>>())

    @After
    fun tearDown() = drain()

    private fun drain() {
        added.toList().forEach { (requestId, _) ->
            BunkerService.respondToApproval(requestId, approved = false)
        }
        added.clear()
    }

    private fun approvalRequest(pubkey: String) = BunkerApprovalRequest(
        appPubkey = pubkey,
        appName = "test-app",
        method = "sign_event",
        eventKind = null,
        eventContent = null,
        requestedPermissions = null,
    )

    private fun add(pubkey: String): Pair<String, Boolean> {
        val requestId = UUID.randomUUID().toString()
        val approval = PendingApproval(
            request = approvalRequest(pubkey),
            onResponse = {},
        )
        val accepted = BunkerService.addPendingApproval(requestId, approval)
        if (accepted) added += requestId to pubkey
        return requestId to accepted
    }

    private fun respond(requestId: String, pubkey: String) {
        BunkerService.respondToApproval(requestId, approved = false)
        added.remove(requestId to pubkey)
    }

    @Test
    fun perClientCapRejectsFourthConcurrentRequest() {
        val pubkey = "aa".repeat(32)
        repeat(3) { assertTrue(add(pubkey).second) }
        assertFalse(add(pubkey).second)
    }

    @Test
    fun respondFreesPerClientSlot() {
        val pubkey = "bb".repeat(32)
        val ids = (0 until 3).map { add(pubkey) }
        ids.forEach { assertTrue(it.second) }
        assertFalse(add(pubkey).second)

        respond(ids.first().first, pubkey)

        assertTrue(add(pubkey).second)
    }

    @Test
    fun clientAtCapDoesNotBlockOtherClient() {
        val clientA = "cc".repeat(32)
        val clientB = "dd".repeat(32)
        repeat(3) { assertTrue(add(clientA).second) }
        assertFalse(add(clientA).second)

        repeat(3) { assertTrue(add(clientB).second) }
        assertFalse(add(clientB).second)
    }

    @Test
    fun globalCapRejectsBeyondTenAcrossDistinctClients() {
        repeat(10) { i ->
            assertTrue(add("%064x".format(i)).second)
        }
        assertFalse(add("%064x".format(999)).second)
    }

    @Test
    fun globalRespondFreesSlot() {
        val firstClient = "%064x".format(0)
        val firstId = add(firstClient)
        assertTrue(firstId.second)
        (1 until 10).forEach { assertTrue(add("%064x".format(it)).second) }
        assertFalse(add("%064x".format(999)).second)

        respond(firstId.first, firstClient)

        assertTrue(add("%064x".format(999)).second)
    }

    /**
     * Exercises the synchronized(approvalLock) check-then-increment under real
     * contention: many threads race to admit the same client at once. The lock makes
     * the cap exact, so precisely MAX_CONCURRENT_PER_CLIENT (3) must win regardless of
     * timing; a dropped lock would let extra adds slip through the count check.
     */
    @Test
    fun concurrentAddsRespectPerClientCap() {
        val pubkey = "ff".repeat(32)
        val threads = 16
        val barrier = CyclicBarrier(threads)
        val accepted = AtomicInteger(0)
        val workers = (0 until threads).map {
            Thread {
                barrier.await()
                if (add(pubkey).second) accepted.incrementAndGet()
            }
        }
        workers.forEach { it.start() }
        workers.forEach { it.join() }
        assertEquals(3, accepted.get())
    }

    @Test
    fun acceptedRequestIsRetrievableAndRemovedOnRespond() {
        val pubkey = "ee".repeat(32)
        val (requestId, accepted) = add(pubkey)
        assertTrue(accepted)
        assertNotNull(BunkerService.getPendingApproval(requestId))

        respond(requestId, pubkey)
        assertNull(BunkerService.getPendingApproval(requestId))
    }
}
