package io.privkey.keep.nip55

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SignedKindBeforeTest {

    private var nextId = 1L

    private fun row(
        decision: String,
        requestId: String? = null,
        caller: String = CALLER,
        kind: Int = KIND,
        entryHash: String = "h${nextId}"
    ) = Nip55AuditLog(
        id = nextId++,
        timestamp = 0,
        callerPackage = caller,
        requestType = "SIGN_EVENT",
        eventKind = kind,
        decision = decision,
        wasAutomatic = true,
        entryHash = entryHash,
        requestId = requestId
    )

    @Test
    fun aChainedApprovalCounts() {
        assertTrue(signedKindBefore(listOf(row("allow", ID_A)), CALLER, KIND))
        assertTrue(signedKindBefore(listOf(row("allow")), CALLER, KIND))
    }

    @Test
    fun onlyThisCallerAndKindCount() {
        val rows = listOf(row("allow", caller = "other.app"), row("allow", kind = 7), row("deny"))
        assertFalse(signedKindBefore(rows, CALLER, KIND))
    }

    @Test
    fun aLegacyRowDoesNotCount() {
        assertFalse(signedKindBefore(listOf(row("allow", entryHash = "")), CALLER, KIND))
    }

    @Test
    fun anApprovalAbandonedAfterItDoesNotCount() {
        val rows = listOf(row("allow", ID_A), row(AUDIT_DECISION_ABANDONED, ID_A))
        assertFalse(signedKindBefore(rows, CALLER, KIND))
    }

    @Test
    fun anAbandonedRowOnlyCancelsItsOwnApproval() {
        val rows = listOf(row("allow", ID_A), row("allow", ID_B), row(AUDIT_DECISION_ABANDONED, ID_A))
        assertTrue(signedKindBefore(rows, CALLER, KIND))
    }

    @Test
    fun anAbandonedRowBeforeTheApprovalDoesNotCancelIt() {
        val rows = listOf(row(AUDIT_DECISION_ABANDONED, ID_A), row("allow", ID_A))
        assertTrue(signedKindBefore(rows, CALLER, KIND))
    }

    @Test
    fun anAbandonedRowMustMatchCallerAndKind() {
        val otherCaller = listOf(row("allow", ID_A), row(AUDIT_DECISION_ABANDONED, ID_A, caller = "other.app"))
        val otherKind = listOf(row("allow", ID_A), row(AUDIT_DECISION_ABANDONED, ID_A, kind = 7))
        assertTrue(signedKindBefore(otherCaller, CALLER, KIND))
        assertTrue(signedKindBefore(otherKind, CALLER, KIND))
    }

    @Test
    fun aLegacyAbandonedRowCancelsNothing() {
        val rows = listOf(row("allow", ID_A), row(AUDIT_DECISION_ABANDONED, ID_A, entryHash = ""))
        assertTrue(signedKindBefore(rows, CALLER, KIND))
    }

    private companion object {
        const val CALLER = "com.example.app"
        const val KIND = 1
        const val ID_A = "0123456789abcdef0123456789abcdef"
        const val ID_B = "fedcba9876543210fedcba9876543210"
    }
}
