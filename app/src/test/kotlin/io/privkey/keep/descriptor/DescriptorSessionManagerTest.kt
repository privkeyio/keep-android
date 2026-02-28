package io.privkey.keep.descriptor

import io.privkey.keep.uniffi.AnnouncedXpubInfo
import io.privkey.keep.uniffi.DescriptorProposal
import io.privkey.keep.uniffi.RecoveryTierConfig
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class DescriptorSessionManagerTest {

    @Before
    fun setup() {
        DescriptorSessionManager.clearAll()
        DescriptorSessionManager.activate()
        DescriptorSessionManager.setCallbacksRegistered(false)
    }

    private fun makeProposal(
        sessionId: String = "session-1",
        network: String = "bitcoin"
    ) = DescriptorProposal(sessionId, network, listOf(RecoveryTierConfig(2u, 6u)))

    private fun makeXpub(
        xpub: String = "xpub6ABC123",
        fingerprint: String = "abcd1234",
        label: String? = "coldcard-backup"
    ) = AnnouncedXpubInfo(xpub, fingerprint, label)

    @Test
    fun `initial state is Idle`() = runTest {
        assertEquals(DescriptorSessionState.Idle, DescriptorSessionManager.state.first())
    }

    @Test
    fun `onProposed transitions to Proposed`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        callbacks.onProposed("session-1")
        assertEquals(DescriptorSessionState.Proposed("session-1"), DescriptorSessionManager.state.first())
    }

    @Test
    fun `onContributionNeeded transitions state and adds proposal`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        val proposal = makeProposal()
        callbacks.onContributionNeeded(proposal)

        assertEquals(DescriptorSessionState.ContributionNeeded(proposal), DescriptorSessionManager.state.first())
        assertEquals(listOf(proposal), DescriptorSessionManager.pendingProposals.first())
    }

    @Test
    fun `onContributed transitions to Contributed`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        callbacks.onContributed("session-1", 0u)
        assertEquals(
            DescriptorSessionState.Contributed("session-1", 0u),
            DescriptorSessionManager.state.first()
        )
    }

    @Test
    fun `onComplete transitions to Complete and removes proposal`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        val proposal = makeProposal()
        callbacks.onContributionNeeded(proposal)
        assertEquals(1, DescriptorSessionManager.pendingProposals.first().size)

        callbacks.onComplete("session-1", "wpkh([ext])", "wpkh([int])")

        val state = DescriptorSessionManager.state.first() as DescriptorSessionState.Complete
        assertEquals("session-1", state.sessionId)
        assertEquals("wpkh([ext])", state.externalDescriptor)
        assertEquals("wpkh([int])", state.internalDescriptor)
        assertTrue(DescriptorSessionManager.pendingProposals.first().isEmpty())
    }

    @Test
    fun `onFailed transitions to Failed and removes proposal`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        val proposal = makeProposal()
        callbacks.onContributionNeeded(proposal)

        callbacks.onFailed("session-1", "timeout")

        val state = DescriptorSessionManager.state.first() as DescriptorSessionState.Failed
        assertEquals("session-1", state.sessionId)
        assertEquals("timeout", state.error)
        assertTrue(DescriptorSessionManager.pendingProposals.first().isEmpty())
    }

    @Test
    fun `propose on each network tracks correct network`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        listOf("bitcoin", "testnet", "signet").forEach { network ->
            DescriptorSessionManager.clearAll()
            DescriptorSessionManager.activate()
            val proposal = makeProposal(sessionId = "session-$network", network = network)
            callbacks.onContributionNeeded(proposal)

            val pending = DescriptorSessionManager.pendingProposals.first()
            assertEquals(1, pending.size)
            assertEquals(network, pending[0].network)
        }
    }

    @Test
    fun `multiple pending proposals accumulate`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        callbacks.onContributionNeeded(makeProposal("s1", "bitcoin"))
        callbacks.onContributionNeeded(makeProposal("s2", "testnet"))
        callbacks.onContributionNeeded(makeProposal("s3", "signet"))

        val pending = DescriptorSessionManager.pendingProposals.first()
        assertEquals(3, pending.size)
        assertEquals(listOf("bitcoin", "testnet", "signet"), pending.map { it.network })
    }

    @Test
    fun `removePendingProposal only removes matching session`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        callbacks.onContributionNeeded(makeProposal("s1", "bitcoin"))
        callbacks.onContributionNeeded(makeProposal("s2", "testnet"))

        DescriptorSessionManager.removePendingProposal("s1")

        val pending = DescriptorSessionManager.pendingProposals.first()
        assertEquals(1, pending.size)
        assertEquals("s2", pending[0].sessionId)
    }

    @Test
    fun `clearSessionState resets state but keeps proposals`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        callbacks.onContributionNeeded(makeProposal())

        DescriptorSessionManager.clearSessionState()

        assertEquals(DescriptorSessionState.Idle, DescriptorSessionManager.state.first())
        assertEquals(1, DescriptorSessionManager.pendingProposals.first().size)
    }

    @Test
    fun `clearAll resets state and proposals`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        callbacks.onContributionNeeded(makeProposal())

        DescriptorSessionManager.clearAll()

        assertEquals(DescriptorSessionState.Idle, DescriptorSessionManager.state.first())
        assertTrue(DescriptorSessionManager.pendingProposals.first().isEmpty())
    }

    @Test
    fun `approve then complete full flow`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        callbacks.onProposed("s1")
        assertTrue(DescriptorSessionManager.state.first() is DescriptorSessionState.Proposed)

        callbacks.onContributionNeeded(makeProposal("s1"))
        assertTrue(DescriptorSessionManager.state.first() is DescriptorSessionState.ContributionNeeded)

        callbacks.onContributed("s1", 1u)
        assertTrue(DescriptorSessionManager.state.first() is DescriptorSessionState.Contributed)

        callbacks.onComplete("s1", "ext-desc", "int-desc")
        val completeState = DescriptorSessionManager.state.first() as DescriptorSessionState.Complete
        assertEquals("ext-desc", completeState.externalDescriptor)
        assertTrue(DescriptorSessionManager.pendingProposals.first().isEmpty())
    }

    @Test
    fun `callbacksRegistered defaults to false and can be set`() = runTest {
        assertFalse(DescriptorSessionManager.callbacksRegistered.first())
        DescriptorSessionManager.setCallbacksRegistered(true)
        assertTrue(DescriptorSessionManager.callbacksRegistered.first())
        DescriptorSessionManager.setCallbacksRegistered(false)
        assertFalse(DescriptorSessionManager.callbacksRegistered.first())
    }

    @Test
    fun `setContributed transitions to Contributed with zero index`() = runTest {
        DescriptorSessionManager.setContributed("s1")
        val state = DescriptorSessionManager.state.first() as DescriptorSessionState.Contributed
        assertEquals("s1", state.sessionId)
        assertEquals(0.toUShort(), state.shareIndex)
    }

    @Test
    fun `local approve then complete flow`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        callbacks.onContributionNeeded(makeProposal("s1"))
        assertTrue(DescriptorSessionManager.state.first() is DescriptorSessionState.ContributionNeeded)

        DescriptorSessionManager.setContributed("s1")
        assertTrue(DescriptorSessionManager.state.first() is DescriptorSessionState.Contributed)

        callbacks.onComplete("s1", "ext-desc", "int-desc")
        val completeState = DescriptorSessionManager.state.first() as DescriptorSessionState.Complete
        assertEquals("ext-desc", completeState.externalDescriptor)
    }

    @Test
    fun `reject flow transitions through Failed`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        callbacks.onContributionNeeded(makeProposal("s1"))
        callbacks.onFailed("s1", "rejected by user")

        assertEquals(
            DescriptorSessionState.Failed("s1", "rejected by user"),
            DescriptorSessionManager.state.first()
        )
        assertTrue(DescriptorSessionManager.pendingProposals.first().isEmpty())
    }

    @Test
    fun `callbacks are ignored after clearAll deactivates`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        DescriptorSessionManager.clearAll()

        callbacks.onProposed("s1")
        assertEquals(DescriptorSessionState.Idle, DescriptorSessionManager.state.first())

        callbacks.onContributionNeeded(makeProposal("s2"))
        assertTrue(DescriptorSessionManager.pendingProposals.first().isEmpty())

        DescriptorSessionManager.activate()
        callbacks.onProposed("s3")
        assertEquals(DescriptorSessionState.Proposed("s3"), DescriptorSessionManager.state.first())
    }

    @Test
    fun `onXpubAnnounced stores announced xpubs`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        val xpubs = listOf(makeXpub())
        callbacks.onXpubAnnounced(1u, xpubs)

        val announced = DescriptorSessionManager.announcedXpubs.first()
        assertEquals(1, announced.size)
        assertEquals(xpubs, announced[1.toUShort()])
    }

    @Test
    fun `multiple shares announce xpubs independently`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        val xpubs1 = listOf(makeXpub("xpub1", "aaaa1111"))
        val xpubs2 = listOf(makeXpub("xpub2", "bbbb2222"), makeXpub("xpub3", "cccc3333"))
        callbacks.onXpubAnnounced(1u, xpubs1)
        callbacks.onXpubAnnounced(2u, xpubs2)

        val announced = DescriptorSessionManager.announcedXpubs.first()
        assertEquals(2, announced.size)
        assertEquals(1, announced[1.toUShort()]?.size)
        assertEquals(2, announced[2.toUShort()]?.size)
    }

    @Test
    fun `clearAll clears announced xpubs`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        callbacks.onXpubAnnounced(1u, listOf(makeXpub()))

        DescriptorSessionManager.clearAll()

        assertTrue(DescriptorSessionManager.announcedXpubs.first().isEmpty())
    }

    @Test
    fun `onXpubAnnounced ignored after clearAll`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        DescriptorSessionManager.clearAll()

        callbacks.onXpubAnnounced(1u, listOf(makeXpub()))

        assertTrue(DescriptorSessionManager.announcedXpubs.first().isEmpty())
    }

    @Test
    fun `announced xpubs initial state is empty`() = runTest {
        assertTrue(DescriptorSessionManager.announcedXpubs.first().isEmpty())
    }

    @Test
    fun `re-announce accumulates xpubs for same share`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        callbacks.onXpubAnnounced(1u, listOf(makeXpub("xpub-old", "11111111")))
        callbacks.onXpubAnnounced(1u, listOf(makeXpub("xpub-new", "22222222")))

        val announced = DescriptorSessionManager.announcedXpubs.first()
        assertEquals(1, announced.size)
        val xpubs = announced[1.toUShort()]!!
        assertEquals(2, xpubs.size)
        assertEquals("xpub-old", xpubs[0].xpub)
        assertEquals("xpub-new", xpubs[1].xpub)
    }

    @Test
    fun `re-announcing same xpub does not duplicate`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        val xpub = makeXpub("xpub-same", "11111111")
        callbacks.onXpubAnnounced(1u, listOf(xpub))
        callbacks.onXpubAnnounced(1u, listOf(xpub))

        val announced = DescriptorSessionManager.announcedXpubs.first()
        assertEquals(1, announced[1.toUShort()]?.size)
    }
}
