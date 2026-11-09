package io.privkey.keep

import io.privkey.keep.uniffi.PendingShareInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PendingDkgDialogTest {

    private val shareA = PendingShareInfo(name = "A", groupPubkey = "aa".repeat(32), vaultProtected = true)
    private val shareB = PendingShareInfo(name = "B", groupPubkey = "bb".repeat(32), vaultProtected = true)

    private fun dialog(
        share: PendingShareInfo? = null,
        unreadable: Boolean = false,
        recovering: Boolean = false,
        confirmingDiscard: Boolean = false,
        deferredFor: String? = null,
    ) = pendingDkgDialogFor(share, unreadable, recovering, confirmingDiscard, deferredFor)

    private fun laterOn(share: PendingShareInfo?, unreadable: Boolean = false) = pendingDkgSubject(share, unreadable)

    @Test
    fun aPendingShareAsksToRecover() {
        assertEquals(PendingDkgDialog.RECOVER, dialog(share = shareA))
    }

    @Test
    fun laterHidesThatShare() {
        assertNull(dialog(share = shareA, deferredFor = laterOn(shareA)))
    }

    @Test
    fun laterOnAShareHoldsThroughAFailedRead() {
        assertNull(dialog(share = shareA, unreadable = true, deferredFor = laterOn(shareA)))
    }

    @Test
    fun laterOnAShareDoesNotHideADifferentShare() {
        assertEquals(PendingDkgDialog.RECOVER, dialog(share = shareB, deferredFor = laterOn(shareA)))
    }

    @Test
    fun laterOnAnUnreadableStashDoesNotHideTheShareOnceItReads() {
        val deferred = laterOn(null, unreadable = true)
        assertNull(dialog(unreadable = true, deferredFor = deferred))
        assertEquals(PendingDkgDialog.RECOVER, dialog(share = shareA, deferredFor = deferred))
    }

    @Test
    fun anUnreadableStashAsksWhatToDo() {
        assertEquals(PendingDkgDialog.UNREADABLE, dialog(unreadable = true))
    }

    @Test
    fun nothingPendingShowsNothingWhateverWasDeferred() {
        assertNull(dialog())
        assertNull(dialog(deferredFor = laterOn(shareA)))
        assertNull(dialog(confirmingDiscard = true))
    }

    @Test
    fun theDiscardConfirmWinsWhileSomethingIsPending() {
        assertEquals(PendingDkgDialog.DISCARD_CONFIRM, dialog(share = shareA, confirmingDiscard = true, deferredFor = laterOn(shareA)))
        assertEquals(PendingDkgDialog.DISCARD_CONFIRM, dialog(unreadable = true, confirmingDiscard = true))
    }

    @Test
    fun aRecoveryInProgressHidesTheRecoverDialog() {
        assertNull(dialog(share = shareA, recovering = true))
    }
}
