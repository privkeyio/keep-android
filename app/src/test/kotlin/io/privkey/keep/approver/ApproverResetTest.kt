package io.privkey.keep.approver

import org.junit.Assert.assertEquals
import org.junit.Test

class ApproverResetTest {

    private var opens = mutableListOf<String?>()
    private var cleared = 0

    private fun reset(unreadable: Boolean) = resetUnreadableApprover(
        open = { opens.removeAt(0) },
        unreadable = { unreadable },
        clear = { cleared++ },
    )

    @Test
    fun aStateThatReadsOnTheRetryIsKept() {
        opens = mutableListOf("paired")
        assertEquals(ApproverReset.Kept("paired"), reset(unreadable = true))
        assertEquals(0, cleared)
    }

    @Test
    fun aFaultThatMayClearIsNotReset() {
        opens = mutableListOf(null)
        assertEquals(ApproverReset.NotReset, reset(unreadable = false))
        assertEquals(0, cleared)
    }

    @Test
    fun aDamagedStateIsClearedAndOpensFresh() {
        opens = mutableListOf(null, "unpaired")
        assertEquals(ApproverReset.Cleared("unpaired"), reset(unreadable = true))
        assertEquals(1, cleared)
    }

    @Test
    fun aClearThatStillDoesNotOpenIsNotReset() {
        opens = mutableListOf(null, null)
        assertEquals(ApproverReset.NotReset, reset(unreadable = true))
        assertEquals(1, cleared)
    }
}
