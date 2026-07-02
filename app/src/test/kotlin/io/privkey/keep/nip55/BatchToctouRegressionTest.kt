package io.privkey.keep.nip55

import io.privkey.keep.uniffi.Nip55RequestType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Regression test for the NIP-55 batch TOCTOU consent-bypass (gh #372, guarding the
 * HIGH finding fixed in 9a9bf6c). It drives the real [BatchConsentGate] that
 * [Nip55Activity] delegates to, so the three guards are exercised at their production
 * call-sites: dropping the lock check from [BatchConsentGate.render]/[commit], or
 * binding a decision to the live pending list instead of the displayed snapshot, fails
 * these tests. The invariant locked in: the signed/rejected set is exactly what was
 * rendered, and a request delivered via a late onNewIntent between render and the
 * user's tap can never join it.
 *
 * The gate transitions mirror the Activity's:
 * - accumulate -> handleIntent (decisionLocked re-entry guard + accumulation)
 * - render     -> setupContent (captures the displayed snapshot)
 * - commit     -> handleApprove/handleReject (locks, binds to displayed)
 */
class BatchToctouRegressionTest {

    private val app = "com.test.app"
    private val other = "com.other.app"
    private val cap = 20

    private fun gate() =
        BatchConsentGate<Pair<String, Nip55RequestType>>(cap) { it.second }

    private fun BatchConsentGate<Pair<String, Nip55RequestType>>.deliver(
        id: String,
        type: Nip55RequestType = Nip55RequestType.SIGN_EVENT,
        caller: String = app,
    ) = accumulate(id to type, caller)

    @Test
    fun lateIntentBetweenRenderAndTapIsNeverSigned() {
        val gate = gate()
        gate.deliver("r1")
        gate.deliver("r2")
        gate.render()

        // Attacker races a request in after the user has seen {r1, r2}.
        gate.deliver("late")

        val signed = gate.commit()

        assertEquals(listOf("r1", "r2"), signed?.map { it.first })
        assertFalse(signed!!.any { it.first == "late" })
    }

    @Test
    fun intentDeliveredAfterDecisionIsIgnored() {
        val gate = gate()
        gate.deliver("r1")
        gate.render()
        gate.commit()

        // Once locked, a late intent must not mutate pending at all.
        gate.deliver("late")

        assertEquals(listOf("r1"), gate.pending.map { it.first })
    }

    @Test
    fun secondDecisionAfterLockIsIgnored() {
        val gate = gate()
        gate.deliver("r1")
        gate.render()
        val first = gate.commit()

        // A committed decision can never run twice.
        val second = gate.commit()

        assertEquals(listOf("r1"), first?.map { it.first })
        assertNull(second)
    }

    @Test
    fun deferredAsyncRenderAfterDecisionDoesNotRecaptureGrownPending() {
        val gate = gate()
        gate.deliver("r1")
        gate.render()

        // The late intent lands before the tap, so it accumulates into pending, but
        // its setupContent is deferred (calculateRiskAndSetupContent launches async)
        // and only fires after the user has already committed the decision.
        gate.deliver("late")
        gate.commit()

        // That deferred render must be blocked by the lock: it cannot re-capture the
        // grown [r1, late] pending into displayed. Without the guard it would.
        gate.render()

        assertEquals(listOf("r1"), gate.displayed.map { it.first })
    }

    @Test
    fun signedSetEqualsDisplayedSnapshotAcrossFullBatch() {
        val gate = gate()
        repeat(5) { gate.deliver("r$it") }
        gate.render()
        val displayedAtRender = gate.displayed.map { it.first }

        gate.deliver("late")
        val signed = gate.commit()!!.map { it.first }

        // The invariant #372 locks in: the signed set is exactly what was rendered.
        assertEquals(displayedAtRender, signed)
    }

    @Test
    fun lateDifferentCallerRaceResetsPendingButNotTheSignedSet() {
        val gate = gate()
        gate.deliver("r1")
        gate.deliver("r2")
        gate.render()

        // A different-caller request resets the batch (pending is cleared and starts
        // fresh), the most adversarial TOCTOU shape: the pending list the user saw is
        // gone by decision time. The decision must still bind to the displayed {r1, r2}.
        gate.deliver("evil", caller = other)
        assertEquals(listOf("evil"), gate.pending.map { it.first })

        val signed = gate.commit()

        assertEquals(listOf("r1", "r2"), signed?.map { it.first })
    }

    @Test
    fun lateGetPublicKeyRaceDoesNotJoinTheSignedSet() {
        val gate = gate()
        gate.deliver("r1")
        gate.render()

        // get_public_key never batches; it resets pending. The signed set is still the
        // displayed snapshot, so the racing get_public_key can never be folded in.
        gate.deliver("pk", type = Nip55RequestType.GET_PUBLIC_KEY)

        val signed = gate.commit()

        assertEquals(listOf("r1"), signed?.map { it.first })
        assertFalse(signed!!.any { it.first == "pk" })
    }
}
