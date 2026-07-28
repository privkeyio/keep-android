package io.privkey.keep.nip55

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import fr.acinq.secp256k1.Secp256k1
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.PeerStatus
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FrostSignHandlerVerifyTest {

    private var mobile: KeepMobile? = null

    @After
    fun tearDown() {
        mobile?.destroy()
        mobile = null
    }

    @Test(timeout = 180_000L)
    fun signEvent_throughHandler_producesValidSchnorrSignature() {
        val manual = InstrumentationRegistry.getArguments().getString(FrostSignFixture.MANUAL_ARG)
        assumeTrue("manual-only test; pass -e ${FrostSignFixture.MANUAL_ARG} 1", manual == "1")
        assumeTrue("SHARE1_EXPORT_DATA not filled in", FrostSignFixture.SHARE1_EXPORT_DATA.isNotEmpty())

        val storage = FrostSignTestSupport.noAuthStorage()
        val mobile = KeepMobile(storage).also { this.mobile = it }

        FrostSignTestSupport.importShareNoAuth(mobile, storage, FrostSignFixture.SHARE1_EXPORT_DATA, "signer-setup")
        FrostSignTestSupport.initializeWithDecryptContext(mobile, storage, "signer-connect")
        val groupPubkeyHex = FrostSignTestSupport.assertFixtureShareLoaded(mobile)
        waitForOnlinePeer(mobile, 90_000L)

        val event = JSONObject().apply {
            put("pubkey", groupPubkeyHex)
            put("created_at", System.currentTimeMillis() / 1000L)
            put("kind", 1)
            put("tags", JSONArray())
            put("content", "frost handler sign test")
        }

        val request = Nip55Request(
            requestType = Nip55RequestType.SIGN_EVENT,
            content = event.toString(),
            pubkey = null,
            returnType = "signature",
            compressionType = "none",
            callbackUrl = null,
            id = "frost-sign-verify",
            currentUser = null,
            permissions = null,
            kind = null,
            scope = null
        )

        // Pre-approve the local node's own participation so the coordinator's
        // pre_sign auto-approves instead of blocking on an interactive prompt
        // (mirrors Nip55Activity/Nip55ContentProvider before the Rust handler).
        mobile.preApproveNostrEvent(event.toString())

        Nip55Handler(mobile).use { handler ->
            val response = handler.handleRequest(request, "io.privkey.keep.test")

            assertNull("Error should be null: ${response.error}", response.error)
            assertEquals("Signature should be 64 bytes (128 hex chars)", 128, response.result.length)

            val signedEvent = JSONObject(requireNotNull(response.event) { "Signed event must not be null" })
            val eventId = signedEvent.getString("id")

            val sig = hexDecode(response.result)
            val msg = hexDecode(eventId)
            val pubkey = hexDecode(groupPubkeyHex)

            assertEquals(64, sig.size)
            assertEquals(32, msg.size)
            assertEquals(32, pubkey.size)

            assertTrue(
                "Schnorr signature must verify against event id and group pubkey",
                Secp256k1.verifySchnorr(sig, msg, pubkey)
            )
        }
    }

    private fun waitForOnlinePeer(mobile: KeepMobile, timeoutMs: Long) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (mobile.getPeers().any { it.status == PeerStatus.ONLINE }) return
            Thread.sleep(1_000L)
        }
        throw AssertionError("No online co-signer peer discovered within ${timeoutMs}ms")
    }

    private fun hexDecode(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(hex.length / 2) { i ->
            val hi = Character.digit(hex[i * 2], 16)
            val lo = Character.digit(hex[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "Invalid hex character in: $hex" }
            ((hi shl 4) + lo).toByte()
        }
    }
}
