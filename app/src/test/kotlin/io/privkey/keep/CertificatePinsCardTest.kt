package io.privkey.keep

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Retiring a pin must warn the operator only when it leaves the host unpinned
 * (re-opening trust-on-first-use), and staging must reject anything that is not
 * a 32-byte SHA-256 SPKI digest before it reaches keep-mobile.
 */
class CertificatePinsCardTest {
    private val hostA = "relay.example.com"
    private val hostB = "relay.other.com"
    private val hashOne = "a".repeat(64)
    private val hashTwo = "b".repeat(64)

    @Test
    fun singlePinForHost_isLastPin() {
        val pins = listOf(CertificatePin(hostA, hashOne))
        assertTrue(isLastPinForHost(pins, hostA))
    }

    @Test
    fun multiplePinsForHost_isNotLastPin() {
        val pins = listOf(CertificatePin(hostA, hashOne), CertificatePin(hostA, hashTwo))
        assertFalse(isLastPinForHost(pins, hostA))
    }

    @Test
    fun countsOnlyMatchingHost() {
        val pins = listOf(CertificatePin(hostA, hashOne), CertificatePin(hostB, hashTwo))
        assertTrue(isLastPinForHost(pins, hostA))
        assertTrue(isLastPinForHost(pins, hostB))
    }

    @Test
    fun unknownHost_isLastPin() {
        assertTrue(isLastPinForHost(emptyList(), hostA))
    }

    @Test
    fun validSpkiHash_is64Hex() {
        assertTrue(isValidSpkiHash("0".repeat(64)))
        assertTrue(isValidSpkiHash("aAbBcCdDeEfF" + "0".repeat(52)))
    }

    @Test
    fun invalidSpkiHash_rejected() {
        assertFalse(isValidSpkiHash(""))
        assertFalse(isValidSpkiHash("a".repeat(63)))
        assertFalse(isValidSpkiHash("a".repeat(65)))
        assertFalse(isValidSpkiHash("g".repeat(64)))
        assertFalse(isValidSpkiHash("z".repeat(64)))
        assertFalse(isValidSpkiHash("  " + "a".repeat(64)))
    }
}
