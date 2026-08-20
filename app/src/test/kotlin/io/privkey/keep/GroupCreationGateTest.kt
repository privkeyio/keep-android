package io.privkey.keep

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Coverage for [groupCreationGate], the fail-closed guard on the group-creation ceremony.
 * The share/unreadable flags default to "nothing pending", so a Create Group tap fired
 * before the initial marker read resolves must not slip past the block and start a DKG
 * that persistence would only reject. Pure logic; the Compose flow is emulator-bound and
 * out of unit scope.
 */
class GroupCreationGateTest {

    @Test
    fun tapDuringInitialReadWaits() =
        assertEquals(
            GroupCreationGate.WAIT,
            groupCreationGate(pendingCheckComplete = false, hasPendingShare = false, pendingUnreadable = false),
        )

    @Test
    fun incompleteCheckWaitsEvenWithKnownShare() =
        assertEquals(
            GroupCreationGate.WAIT,
            groupCreationGate(pendingCheckComplete = false, hasPendingShare = true, pendingUnreadable = false),
        )

    @Test
    fun incompleteCheckWaitsEvenWhenUnreadable() =
        assertEquals(
            GroupCreationGate.WAIT,
            groupCreationGate(pendingCheckComplete = false, hasPendingShare = false, pendingUnreadable = true),
        )

    @Test
    fun completedCheckWithPendingShareBlocks() =
        assertEquals(
            GroupCreationGate.BLOCK,
            groupCreationGate(pendingCheckComplete = true, hasPendingShare = true, pendingUnreadable = false),
        )

    @Test
    fun completedCheckWithUnreadableMarkerBlocks() =
        assertEquals(
            GroupCreationGate.BLOCK,
            groupCreationGate(pendingCheckComplete = true, hasPendingShare = false, pendingUnreadable = true),
        )

    @Test
    fun completedCheckWithClearSlotAllows() =
        assertEquals(
            GroupCreationGate.ALLOW,
            groupCreationGate(pendingCheckComplete = true, hasPendingShare = false, pendingUnreadable = false),
        )
}
