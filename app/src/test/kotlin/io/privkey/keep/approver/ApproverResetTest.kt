package io.privkey.keep.approver

import io.privkey.keep.storage.ApproverStateFile.LoadResult
import io.privkey.keep.uniffi.KeepMobileException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApproverResetTest {

    private var opens = mutableListOf<String?>()
    private var damaged = mutableListOf<Boolean>()
    private var cleared = 0

    private fun reset() = resetUnreadableApprover(
        open = { opens.removeAt(0) },
        damaged = { damaged.removeAt(0) },
        clear = { cleared++ },
    )

    @Test
    fun aStateThatReadsOnARetryIsKept() {
        opens = mutableListOf("paired")
        assertEquals(ApproverReset.Kept("paired"), reset())
        opens = mutableListOf(null, "paired")
        damaged = mutableListOf(true)
        assertEquals(ApproverReset.Kept("paired"), reset())
        assertEquals(0, cleared)
    }

    @Test
    fun aFaultThatMayClearIsNotReset() {
        opens = mutableListOf(null)
        damaged = mutableListOf(false)
        assertEquals(ApproverReset.NotReset, reset())
        opens = mutableListOf(null, null)
        damaged = mutableListOf(true, false)
        assertEquals(ApproverReset.NotReset, reset())
        assertEquals(0, cleared)
    }

    @Test
    fun aStateDamagedTwiceIsClearedAndOpensFresh() {
        opens = mutableListOf(null, null, "unpaired")
        damaged = mutableListOf(true, true)
        assertEquals(ApproverReset.Cleared("unpaired"), reset())
        assertEquals(1, cleared)
    }

    @Test
    fun aClearThatStillDoesNotOpenIsNotReset() {
        opens = mutableListOf(null, null, null)
        damaged = mutableListOf(true, true)
        assertEquals(ApproverReset.NotReset, reset())
        assertEquals(1, cleared)
    }

    @Test
    fun onlyAStorageErrorOverDamagedOrRefusedBytesIsDamaged() {
        val storage = KeepMobileException.StorageException("x")
        assertTrue(approverDamaged(storage, LoadResult.DAMAGED))
        assertTrue(approverDamaged(storage, LoadResult.READABLE))
        assertFalse(approverDamaged(storage, LoadResult.FAULT))
        assertFalse(approverDamaged(storage, LoadResult.ABSENT))
        assertFalse(approverDamaged(storage, null))
        assertFalse(approverDamaged(KeepMobileException.InitializationFailed("x"), LoadResult.DAMAGED))
        assertFalse(approverDamaged(null, LoadResult.DAMAGED))
    }
}
