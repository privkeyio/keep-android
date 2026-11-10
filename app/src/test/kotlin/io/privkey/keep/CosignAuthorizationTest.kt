package io.privkey.keep

import io.privkey.keep.uniffi.SignRequest
import io.privkey.keep.uniffi.SignRequestMetadata
import io.privkey.keep.uniffi.SpendOutput
import io.privkey.keep.uniffi.SpendSummary
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class CosignAuthorizationTest {

    private fun request(spend: SpendSummary?) = SignRequest(
        id = "id",
        sessionId = ByteArray(0),
        messageType = "bitcoin-sighash",
        typeVerified = true,
        messagePreview = "ffeeddccbbaa9988",
        fromPeer = 2u,
        timestamp = 0uL,
        metadata = SignRequestMetadata(null, null, null, null, spend),
    )

    private fun other(messageType: String, typeVerified: Boolean, metadata: SignRequestMetadata?) =
        request(null).copy(messageType = messageType, typeVerified = typeVerified, metadata = metadata)

    private val nostrEvent = SignRequestMetadata(1u, "hello", null, null, null)

    private val spend = SpendSummary(listOf(SpendOutput(99_000uL, "tb1qexample", "0014")), 100_000uL, 1_000uL)

    private class Prompts(var strongAnswer: Boolean = true, var usualAnswer: Boolean = true) {
        var strong = 0
        var usual = 0
    }

    private suspend fun authorize(req: SignRequest, secure: Boolean?, prompts: Prompts) = authorizeCosign(
        req,
        deviceSecure = { secure },
        strongOrCredential = { prompts.strong++; prompts.strongAnswer },
        usual = { prompts.usual++; prompts.usualAnswer },
    )

    @Test
    fun `every spend approval asks for a strong biometric or the credential, never the usual window`() = runTest {
        val prompts = Prompts()
        repeat(2) { assertEquals(CosignApproval.APPROVED, authorize(request(spend), true, prompts)) }
        assertEquals("a fresh prompt each time", 2, prompts.strong)
        assertEquals("the timeout window is never consulted", 0, prompts.usual)
    }

    @Test
    fun `a spend the person does not confirm is not approved`() = runTest {
        val prompts = Prompts(strongAnswer = false)
        assertEquals(CosignApproval.NOT_AUTHENTICATED, authorize(request(spend), true, prompts))
    }

    @Test
    fun `a device with no screen lock cannot approve a spend and is told why`() = runTest {
        val prompts = Prompts()
        assertEquals(CosignApproval.NO_SCREEN_LOCK, authorize(request(spend), false, prompts))
        assertEquals(0, prompts.strong + prompts.usual)
    }

    @Test
    fun `an unknown lock state refuses a spend`() = runTest {
        val prompts = Prompts()
        assertEquals(CosignApproval.NOT_AUTHENTICATED, authorize(request(spend), null, prompts))
        assertEquals(0, prompts.strong + prompts.usual)
    }

    @Test
    fun `a verified nostr event keeps the usual authentication`() = runTest {
        val event = other("nostr-event", typeVerified = true, metadata = nostrEvent).copy(needsFreshAuth = false)
        val prompts = Prompts()
        assertEquals(CosignApproval.APPROVED, authorize(event, false, prompts))
        assertEquals(1, prompts.usual)
        assertEquals(0, prompts.strong)
        prompts.usualAnswer = false
        assertEquals(CosignApproval.NOT_AUTHENTICATED, authorize(event, true, prompts))
    }

    @Test
    fun `a verified nostr event the core marks for fresh authentication takes the strict path`() = runTest {
        listOf(3u, 9321u, 30000u).forEach { kind ->
            val event = other("nostr-event", typeVerified = true, metadata = SignRequestMetadata(kind, "x", null, null, null))
            val prompts = Prompts()
            assertEquals(CosignApproval.APPROVED, authorize(event, true, prompts))
            assertEquals("kind $kind asks for a fresh prompt", 1, prompts.strong)
            assertEquals(0, prompts.usual)
            assertEquals(CosignApproval.NO_SCREEN_LOCK, authorize(event, false, prompts))
        }
    }

    @Test
    fun `an untweaked sighash sent without its transaction takes the strict path`() = runTest {
        val bare = other("bitcoin-sighash", typeVerified = false, metadata = null)
        val prompts = Prompts()
        assertEquals(CosignApproval.APPROVED, authorize(bare, true, prompts))
        assertEquals(1, prompts.strong)
        assertEquals(0, prompts.usual)
        assertEquals(CosignApproval.NO_SCREEN_LOCK, authorize(bare, false, prompts))
        assertEquals(CosignApproval.NOT_AUTHENTICATED, authorize(bare, null, prompts))
        prompts.strongAnswer = false
        assertEquals(CosignApproval.NOT_AUTHENTICATED, authorize(bare, true, prompts))
        assertEquals(0, prompts.usual)
    }

    @Test
    fun `an unverified or unknown request takes the strict path`() = runTest {
        listOf(
            other("nostr-event", typeVerified = false, metadata = nostrEvent),
            other("some-label", typeVerified = false, metadata = null),
            other("bitcoin-sighash", typeVerified = true, metadata = SignRequestMetadata(null, null, null, null, null)),
        ).forEach { req ->
            val prompts = Prompts()
            assertEquals(CosignApproval.APPROVED, authorize(req, true, prompts))
            assertEquals("${req.messageType} asks for a fresh prompt", 1, prompts.strong)
            assertEquals(0, prompts.usual)
            assertEquals(CosignApproval.NO_SCREEN_LOCK, authorize(req, false, prompts))
        }
    }
}
