package io.privkey.keep.nip55

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import fr.acinq.secp256k1.Secp256k1
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.PeerStatus
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FrostSignHandlerVerifyTest {

    @Test(timeout = 180_000L)
    fun signEvent_throughHandler_producesValidSchnorrSignature() {
        val manual = InstrumentationRegistry.getArguments().getString(FrostSignFixture.MANUAL_ARG)
        assumeTrue("manual-only test; pass -e ${FrostSignFixture.MANUAL_ARG} 1", manual == "1")
        assumeTrue("SHARE1_EXPORT_DATA not filled in", FrostSignFixture.SHARE1_EXPORT_DATA.isNotEmpty())

        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val storage = AndroidKeystoreStorage(context, requireUserAuth = false)
        val mobile = KeepMobile(storage)

        importShareNoAuth(mobile, storage, FrostSignFixture.SHARE1_EXPORT_DATA, "signer-setup")
        initializeWithDecryptContext(mobile, storage, "signer-connect")
        waitForOnlinePeer(mobile, 90_000L)

        val handler = Nip55Handler(mobile)
        val groupPubkeyHex = requireNotNull(mobile.getShareInfo()) { "ShareInfo must not be null" }.groupPubkey

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
            permissions = null
        )

        // Pre-approve the local node's own participation so the coordinator's
        // pre_sign auto-approves instead of blocking on an interactive prompt
        // (mirrors Nip55Activity/Nip55ContentProvider before the Rust handler).
        mobile.preApproveNostrEvent(event.toString())

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

    private fun importShareNoAuth(
        mobile: KeepMobile,
        storage: AndroidKeystoreStorage,
        exportData: String,
        requestId: String,
    ) {
        if (storage.hasShare()) return
        val cipher = storage.getCipherForEncryption()
        storage.setRequestIdContext(requestId)
        storage.setPendingCipher(requestId, cipher)
        try {
            mobile.importShare(exportData, FrostSignFixture.PASSPHRASE, "test")
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
        }
    }

    private fun initializeWithDecryptContext(
        mobile: KeepMobile,
        storage: AndroidKeystoreStorage,
        requestId: String,
    ) {
        val cipher = requireNotNull(storage.getCipherForDecryption()) { "decryption cipher must not be null" }
        storage.setPendingCipher(requestId, cipher)
        storage.setRequestIdContext(requestId)
        try {
            mobile.initialize(listOf(FrostSignFixture.RELAY))
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
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
            ((Character.digit(hex[i * 2], 16) shl 4) + Character.digit(hex[i * 2 + 1], 16)).toByte()
        }
    }
}
