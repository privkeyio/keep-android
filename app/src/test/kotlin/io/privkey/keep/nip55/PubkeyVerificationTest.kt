package io.privkey.keep.nip55

import io.privkey.keep.uniffi.Nip55RequestType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Regression coverage for the get_public_key integrity gate (gh #330), which
 * blocks persisting grants/trust and returning a result when a handler's pubkey
 * does not match the stored group pubkey. The Activity wiring (storage/result
 * codes) is native-bound and out of unit scope.
 */
class PubkeyVerificationTest {

    private val pubkeyBytes = ByteArray(32) { it.toByte() }
    private val pubkeyHex = pubkeyBytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    @Test
    fun emptyResultFails() {
        assertEquals(
            "pubkey_verification_failed",
            checkPubkey(Nip55RequestType.GET_PUBLIC_KEY, "", pubkeyBytes)
        )
    }

    @Test
    fun nullStoredKeyFails() {
        assertEquals(
            "pubkey_verification_failed",
            checkPubkey(Nip55RequestType.GET_PUBLIC_KEY, pubkeyHex, null)
        )
    }

    @Test
    fun emptyStoredKeyFails() {
        assertEquals(
            "pubkey_verification_failed",
            checkPubkey(Nip55RequestType.GET_PUBLIC_KEY, pubkeyHex, ByteArray(0))
        )
    }

    @Test
    fun mismatchFails() {
        val other = ByteArray(32) { (it + 1).toByte() }
        assertEquals(
            "pubkey_verification_failed",
            checkPubkey(Nip55RequestType.GET_PUBLIC_KEY, pubkeyHex, other)
        )
    }

    @Test
    fun exactMatchPasses() {
        assertNull(checkPubkey(Nip55RequestType.GET_PUBLIC_KEY, pubkeyHex, pubkeyBytes))
    }

    @Test
    fun nonGetPublicKeyTypePasses() {
        // Operation requests carry no pubkey to verify, so they trivially pass even
        // with empty result and missing stored key.
        assertNull(checkPubkey(Nip55RequestType.SIGN_EVENT, "", null))
    }
}
