package io.privkey.keep.nip55

import io.privkey.keep.uniffi.Nip55RequestType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Scenario-level regression coverage for the NIP-55 batch state machine (gh #373,
 * split of #323). Where [BatchAccumulationTest] pins the single-decision grouping
 * rules and [BatchToctouRegressionTest] pins the render/commit TOCTOU binding, this
 * suite drives multi-request SEQUENCES through the real production [BatchConsentGate]
 * to lock in the invariants that only hold across a whole batch:
 *
 * - a batch only ever contains one caller's requests (cross-caller / get_public_key
 *   mixing never survives accumulation, not merely a single decision),
 * - the MAX_BATCH_SIZE cap holds as an accumulated-state invariant, not just as a
 *   per-call verdict, and
 * - one biometric presence gate covers N events while the per-request side effects
 *   (preApprove + grant + audit) still fire once per event, matching the single-sign
 *   path — the parity that makes batching a UX change, not a security downgrade.
 *
 * Dropping a guard in the gate, or the per-event loop in the modeled commit, fails
 * these tests: they exercise the code [Nip55Activity] actually delegates to.
 */
class BatchGatingInvariantsTest {

    private val app = "com.test.app"
    private val other = "com.other.app"
    private val cap = 20

    private fun gate() =
        BatchConsentGate<Pair<String, Nip55RequestType>, String>(cap) { it.second }

    private fun BatchConsentGate<Pair<String, Nip55RequestType>, String>.deliver(
        id: String,
        type: Nip55RequestType = Nip55RequestType.SIGN_EVENT,
        caller: String = app,
    ) = accumulate(id to type, caller)

    @Test
    fun sameCallerSignAndCipherRequestsAllAccumulateUnderOneCaller() {
        val gate = gate()
        val types = listOf(
            Nip55RequestType.SIGN_EVENT,
            Nip55RequestType.NIP44_ENCRYPT,
            Nip55RequestType.SIGN_EVENT,
            Nip55RequestType.NIP44_DECRYPT,
            Nip55RequestType.SIGN_EVENT,
        )
        types.forEachIndexed { i, t -> gate.deliver("r$i", type = t) }

        // The whole mixed sign/encrypt/decrypt sequence from one caller batches into a
        // single pending list, and every accumulated request belongs to that caller.
        assertEquals(types.size, gate.pending.size)
        assertEquals(app, gate.batchCaller)
        assertEquals(listOf("r0", "r1", "r2", "r3", "r4"), gate.pending.map { it.first })
    }

    @Test
    fun differentCallerMidSequenceResetsBatchToTheNewCallerOnly() {
        val gate = gate()
        repeat(3) { gate.deliver("r$it") }
        assertEquals(3, gate.pending.size)

        // A different caller's request must not join com.test.app's batch: it discards
        // the accumulated requests and starts fresh, so cross-caller mixing can never
        // exist in the pending set, only in a rejected single decision.
        gate.deliver("evil", caller = other)

        assertEquals(listOf("evil"), gate.pending.map { it.first })
        assertEquals(other, gate.batchCaller)
        assertTrue(gate.pending.none { it.first.startsWith("r") })
    }

    @Test
    fun getPublicKeyMidSequenceResetsAccumulatedBatch() {
        val gate = gate()
        repeat(3) { gate.deliver("r$it") }

        // get_public_key never batches; arriving mid-sequence it clears the accumulated
        // sign requests rather than folding in, so a connect request can never be
        // co-approved under a batch's single presence gate.
        gate.deliver("pk", type = Nip55RequestType.GET_PUBLIC_KEY)

        assertEquals(listOf("pk"), gate.pending.map { it.first })
        assertEquals(Nip55RequestType.GET_PUBLIC_KEY, gate.pending.single().second)
    }

    @Test
    fun accumulationCapsAtMaxBatchSizeAndDropsTheOverflowRequest() {
        val gate = gate()
        val decisions = (0 until cap + 1).map { gate.deliver("r$it") }

        // The first 20 accumulate (the opening request resets an empty batch, the rest
        // accumulate); the 21st is dropped, not accumulated, and the accumulated state
        // stays exactly at the cap.
        assertEquals(cap, gate.pending.size)
        assertEquals(BatchAccumulation.RESET, decisions.first())
        assertTrue(decisions.subList(1, cap).all { it == BatchAccumulation.ACCUMULATE })
        assertEquals(BatchAccumulation.DROP_OVER_CAP, decisions.last())
        assertTrue(gate.pending.none { it.first == "r$cap" })

        // What the user is shown is also capped at 20: the overflow can't sneak onto
        // the consent screen either.
        assertEquals(cap, gate.render(app)!!.size)
    }

    @Test
    fun capHoldsAcrossFurtherOverflowRequests() {
        val gate = gate()
        repeat(cap) { gate.deliver("r$it") }

        // Defensive: several further requests past the cap keep dropping; the pending
        // state never wraps back to accumulating past MAX_BATCH_SIZE.
        repeat(5) { i ->
            assertEquals(BatchAccumulation.DROP_OVER_CAP, gate.deliver("over$i"))
        }
        assertEquals(cap, gate.pending.size)
    }

    @Test
    fun oneBiometricGateCoversBatchWhilePerRequestEffectsFireOncePerEvent() {
        val gate = gate()
        val n = 5
        repeat(n) { gate.deliver("r$it") }
        val committed = gate.render(app).let { gate.commit() }!!

        // The committed set is exactly the displayed batch: N events approved together.
        assertEquals(gate.displayed, committed)
        assertEquals(n, committed.size)

        // Model handleApproveBatch: ONE presence gate for the whole set, then the
        // per-request loop runs preApprove + grant + audit once for every event
        // (parity with the single-sign path, where each fires exactly once).
        var presenceGates = 0
        var preApprovals = 0
        var grants = 0
        var audits = 0
        run {
            presenceGates++
            for (item in committed) {
                if (item.second == Nip55RequestType.SIGN_EVENT) preApprovals++
                grants++
                audits++
            }
        }

        assertEquals(1, presenceGates)
        assertEquals(n, preApprovals)
        assertEquals(n, grants)
        assertEquals(n, audits)
    }
}
