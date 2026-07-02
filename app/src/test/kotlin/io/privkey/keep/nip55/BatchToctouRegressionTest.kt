package io.privkey.keep.nip55

import io.privkey.keep.uniffi.Nip55RequestType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Composition-level regression test for the NIP-55 batch TOCTOU consent-bypass
 * (gh #372, guarding the HIGH finding fixed in 9a9bf6c). The per-helper tests
 * ([ConsentGuardTest], [BatchAccumulationTest]) prove each guard in isolation;
 * this test wires the same three pure guards
 * ([batchAccumulationDecision], [consentActionAdmitted], [consentBoundSet]) into a
 * faithful model of the [Nip55Activity] singleTop batch state machine and drives
 * the actual attack: a request delivered via a late onNewIntent between render and
 * the user's tap must never join the signed/rejected set.
 *
 * The model mirrors the Activity transitions exactly:
 * - deliverIntent -> handleIntent (decisionLocked re-entry guard + accumulation)
 * - render        -> setupContent (captures the displayed snapshot)
 * - approve/reject -> handleApprove/handleReject (locks, binds to displayed)
 */
class BatchToctouRegressionTest {

    private val app = "com.test.app"
    private val cap = 20

    /** Minimal mirror of the Activity's batch state, driven only by the real guards. */
    private class BatchGate(private val cap: Int) {
        val pending = mutableListOf<Pair<String, Nip55RequestType>>()
        var batchCaller: String? = null
        var displayed: List<Pair<String, Nip55RequestType>> = emptyList()
            private set
        var decisionLocked = false
            private set

        /** Mirrors handleIntent: ignored once locked, else accumulate/reset/drop. */
        fun deliverIntent(id: String, type: Nip55RequestType, caller: String) {
            if (!consentActionAdmitted(decisionLocked)) return
            when (
                batchAccumulationDecision(
                    pendingTypes = pending.map { it.second },
                    pendingCaller = batchCaller,
                    newType = type,
                    newCaller = caller,
                    maxBatchSize = cap
                )
            ) {
                BatchAccumulation.DROP_OVER_CAP -> return
                BatchAccumulation.RESET -> pending.clear()
                BatchAccumulation.ACCUMULATE -> {}
            }
            pending.add(id to type)
            batchCaller = caller
        }

        /** Mirrors setupContent: captures what the user sees, guarded by the lock. */
        fun render() {
            if (!consentActionAdmitted(decisionLocked)) return
            displayed = pending.toList()
        }

        /** Mirrors handleApprove/handleReject: locks and binds to the displayed snapshot. */
        fun commitDecision(): List<Pair<String, Nip55RequestType>>? {
            if (!consentActionAdmitted(decisionLocked)) return null
            decisionLocked = true
            return consentBoundSet(displayed, pending)
        }
    }

    @Test
    fun lateIntentBetweenRenderAndTapIsNeverSigned() {
        val gate = BatchGate(cap)
        gate.deliverIntent("r1", Nip55RequestType.SIGN_EVENT, app)
        gate.deliverIntent("r2", Nip55RequestType.SIGN_EVENT, app)
        gate.render()

        // Attacker races a request in after the user has seen {r1, r2}.
        gate.deliverIntent("late", Nip55RequestType.SIGN_EVENT, app)

        val signed = gate.commitDecision()

        assertEquals(listOf("r1", "r2"), signed?.map { it.first })
        assertFalse(signed!!.any { it.first == "late" })
    }

    @Test
    fun intentDeliveredAfterDecisionIsIgnored() {
        val gate = BatchGate(cap)
        gate.deliverIntent("r1", Nip55RequestType.SIGN_EVENT, app)
        gate.render()
        gate.commitDecision()

        // Once locked, a late intent must not mutate pending at all.
        gate.deliverIntent("late", Nip55RequestType.SIGN_EVENT, app)

        assertEquals(listOf("r1"), gate.pending.map { it.first })
    }

    @Test
    fun secondDecisionAfterLockIsIgnored() {
        val gate = BatchGate(cap)
        gate.deliverIntent("r1", Nip55RequestType.SIGN_EVENT, app)
        gate.render()
        val first = gate.commitDecision()

        // A committed decision can never run twice.
        val second = gate.commitDecision()

        assertEquals(listOf("r1"), first?.map { it.first })
        assertNull(second)
    }

    @Test
    fun deferredAsyncRenderAfterDecisionDoesNotRecaptureGrownPending() {
        val gate = BatchGate(cap)
        gate.deliverIntent("r1", Nip55RequestType.SIGN_EVENT, app)
        gate.render()

        // The late intent lands before the tap, so it accumulates into pending, but
        // its setupContent is deferred (calculateRiskAndSetupContent launches async)
        // and only fires after the user has already committed the decision.
        gate.deliverIntent("late", Nip55RequestType.SIGN_EVENT, app)
        gate.commitDecision()

        // That deferred render must be blocked by the lock: it cannot re-capture the
        // grown [r1, late] pending into displayed. Without the guard it would.
        gate.render()

        assertEquals(listOf("r1"), gate.displayed.map { it.first })
    }

    @Test
    fun signedSetEqualsDisplayedSnapshotAcrossFullBatch() {
        val gate = BatchGate(cap)
        repeat(5) { gate.deliverIntent("r$it", Nip55RequestType.SIGN_EVENT, app) }
        gate.render()
        val displayedAtRender = gate.displayed.map { it.first }

        gate.deliverIntent("late", Nip55RequestType.SIGN_EVENT, app)
        val signed = gate.commitDecision()!!.map { it.first }

        // The invariant #372 locks in: the signed set is exactly what was rendered.
        assertEquals(displayedAtRender, signed)
    }
}
