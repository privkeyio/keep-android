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
    fun `a request with no spend keeps the usual authentication`() = runTest {
        val prompts = Prompts()
        assertEquals(CosignApproval.APPROVED, authorize(request(null), false, prompts))
        assertEquals(1, prompts.usual)
        assertEquals(0, prompts.strong)
        prompts.usualAnswer = false
        assertEquals(CosignApproval.NOT_AUTHENTICATED, authorize(request(null), true, prompts))
    }
}
