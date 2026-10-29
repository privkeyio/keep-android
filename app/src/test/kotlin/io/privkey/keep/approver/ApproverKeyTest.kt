package io.privkey.keep.approver

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class ApproverKeyTest {
    private fun hex(s: String) = BigInteger(s, 16)

    @Test
    fun compressesTheP256Generator() {
        val x = hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
        val y = hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
        val expected = BigInteger("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
            .toByteArray()
        assertArrayEquals(expected, ApproverKey.compress(x, y))
    }

    @Test
    fun dropsTheSignByteAndPadsShortCoordinates() {
        val high = hex("f".repeat(64))
        val out = ApproverKey.compress(high, BigInteger.TWO)
        assertEquals(33, out.size)
        assertEquals(0x02.toByte(), out[0])
        assertArrayEquals(ByteArray(32) { 0xff.toByte() }, out.copyOfRange(1, 33))

        val short = ApproverKey.compress(BigInteger.ONE, BigInteger.ONE)
        assertEquals(0x03.toByte(), short[0])
        assertArrayEquals(ByteArray(31) + byteArrayOf(1), short.copyOfRange(1, 33))
    }

    @Test
    fun roundTripsRandomKeysThroughTheCurve() {
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val p = (params.curve.field as java.security.spec.ECFieldFp).p
        val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        repeat(32) {
            val key = generator.generateKeyPair().public as ECPublicKey
            val compressed = ApproverKey.compress(key.w.affineX, key.w.affineY)
            val x = BigInteger(1, compressed.copyOfRange(1, 33))
            val rhs = x.pow(3).add(params.curve.a.multiply(x)).add(params.curve.b).mod(p)
            var y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p)
            if (y.testBit(0) != (compressed[0] == 0x03.toByte())) y = p.subtract(y)
            val rebuilt = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
            assertArrayEquals(key.encoded, rebuilt.encoded)
        }
    }
}

class WaitingRequestTest {
    private val request = io.privkey.keep.uniffi.ApprovalRequest(
        requestId = "00".repeat(32),
        op = "sign_nostr_event",
        reason = "kind 0",
        credential = null,
        secondsLeft = 30u,
        fields = emptyList(),
        warnings = emptyList(),
    )

    @Test
    fun countsDownOnTheMonotonicClockAndStopsAtZero() {
        val waiting = WaitingRequest(request, deadlineElapsedMs = 30_000)
        assertEquals(30, waiting.secondsLeft(0))
        assertEquals(1, waiting.secondsLeft(29_000))
        assertEquals(0, waiting.secondsLeft(30_000))
        assertEquals(0, waiting.secondsLeft(90_000))
    }
}
