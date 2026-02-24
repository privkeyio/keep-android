package io.privkey.keep.descriptor

import io.privkey.keep.uniffi.DescriptorProposal
import io.privkey.keep.uniffi.RecoveryTierConfig
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class DescriptorSessionManagerTest {

    @Before
    fun setup() {
        DescriptorSessionManager.clearAll()
    }

    private fun makeProposal(
        sessionId: String = "session-1",
        network: String = "bitcoin"
    ) = DescriptorProposal(sessionId, network, listOf(RecoveryTierConfig(2u, 6u)))

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
        val state = DescriptorSessionManager.state.first()
        assertTrue(state is DescriptorSessionState.Contributed)
        assertEquals("session-1", (state as DescriptorSessionState.Contributed).sessionId)
        assertEquals(0.toUShort(), state.shareIndex)
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
        val final_ = DescriptorSessionManager.state.first() as DescriptorSessionState.Complete
        assertEquals("ext-desc", final_.externalDescriptor)
        assertTrue(DescriptorSessionManager.pendingProposals.first().isEmpty())
    }

    @Test
    fun `reject flow transitions through Failed`() = runTest {
        val callbacks = DescriptorSessionManager.createCallbacks()
        callbacks.onContributionNeeded(makeProposal("s1"))
        callbacks.onFailed("s1", "rejected by user")

        val state = DescriptorSessionManager.state.first()
        assertTrue(state is DescriptorSessionState.Failed)
        assertEquals("rejected by user", (state as DescriptorSessionState.Failed).error)
        assertTrue(DescriptorSessionManager.pendingProposals.first().isEmpty())
    }
}
