package io.privkey.keep.nip55

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression coverage for the two Activity-bound NIP-55 consent guards (gh #354,
 * follow-up to #326): the [decisionLocked] re-entry guard and the displayed-snapshot
 * binding. Both are extracted as pure functions so the security invariants — a
 * committed decision never runs twice, and the decision acts only on what was on
 * screen — are testable without an instrumented Activity harness.
 */
class ConsentGuardTest {

    @Test
    fun actionAdmittedWhenNotLocked() {
        assertTrue(consentActionAdmitted(decisionLocked = false))
    }

    @Test
    fun actionIgnoredWhenLocked() {
        // Once a decision is committed, every later action is ignored. This single
        // predicate guards all locked-path call sites: a second approve/reject tap
        // (handleApprove/handleReject), a late-arriving intent (handleIntent), and a
        // late async render (calculateRiskAndSetupContent/setupContent).
        assertFalse(consentActionAdmitted(decisionLocked = true))
    }

    @Test
    fun boundSetIsTheDisplayedSnapshot() {
        val displayed = listOf("a", "b")
        val pending = listOf("a", "b")
        assertEquals(displayed, consentBoundSet(displayed, pending))
    }

    @Test
    fun boundSetIgnoresLatePendingMutation() {
        // A request that races in after render is appended to the live pending list.
        // The decision must still act on the displayed snapshot, never the grown list,
        // so the late request can never be folded into the signed set.
        val displayed = listOf("a", "b")
        val pending = mutableListOf("a", "b")

        val bound = consentBoundSet(displayed, pending)

        pending.add("late")

        assertEquals(listOf("a", "b"), bound)
        assertFalse(bound.contains("late"))
    }

    @Test
    fun boundSetReturnsDisplayedEvenWhenPendingDiverges() {
        // Even when pending has already diverged at decision time, the bound set is
        // exactly the displayed snapshot.
        val displayed = listOf("a")
        val pending = listOf("a", "b", "c")
        assertSame(displayed, consentBoundSet(displayed, pending))
    }
}
