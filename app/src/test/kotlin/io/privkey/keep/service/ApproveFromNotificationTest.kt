package io.privkey.keep.service

import io.privkey.keep.uniffi.SignRequest
import io.privkey.keep.uniffi.SignRequestMetadata
import io.privkey.keep.uniffi.SpendOutput
import io.privkey.keep.uniffi.SpendSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApproveFromNotificationTest {

    private fun request(id: String, spend: SpendSummary? = null) = SignRequest(
        id = id,
        sessionId = ByteArray(0),
        messageType = "nostr-event",
        typeVerified = true,
        messagePreview = "abcd1234abcd1234",
        fromPeer = 2u,
        timestamp = 0uL,
        metadata = SignRequestMetadata(1u, null, null, null, spend),
    )

    private val approved = mutableListOf<String>()

    @Test
    fun `a pending request that is not a spend is approved`() {
        assertTrue(approveFromNotification(listOf(request("a"), request("b")), "b") { approved += it })
        assertEquals(listOf("b"), approved)
    }

    @Test
    fun `a request no longer pending is not approved`() {
        assertFalse(approveFromNotification(listOf(request("a")), "gone") { approved += it })
        assertTrue(approved.isEmpty())
    }

    @Test
    fun `nothing is approved before the app has state`() {
        assertFalse(approveFromNotification(null, "a") { approved += it })
        assertTrue(approved.isEmpty())
    }

    @Test
    fun `an unverified request is not approved`() {
        val bare = request("a").copy(messageType = "bitcoin-sighash", typeVerified = false, metadata = null)
        assertFalse(approveFromNotification(listOf(bare), "a") { approved += it })
        assertTrue(approved.isEmpty())
    }

    @Test
    fun `a spend is not approved`() {
        val spend = SpendSummary(listOf(SpendOutput(99_000uL, null, "0014")), 100_000uL, 1_000uL)
        assertFalse(approveFromNotification(listOf(request("a", spend)), "a") { approved += it })
        assertTrue(approved.isEmpty())
    }
}
