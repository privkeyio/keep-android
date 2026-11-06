package io.privkey.keep

import io.privkey.keep.uniffi.SignRequest
import io.privkey.keep.service.CosignNotifier
import io.privkey.keep.uniffi.SignRequestMetadata
import io.privkey.keep.uniffi.SpendOutput
import io.privkey.keep.uniffi.SpendSummary
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The summary this produces is the whole basis on which someone approves a
 * co-sign request, so what it omits matters as much as what it shows.
 */
class SignRequestDescribeTest {

    private fun request(
        messageType: String = "nostr-event",
        messagePreview: String = "abcd1234abcd1234",
        metadata: SignRequestMetadata? = null,
        typeVerified: Boolean = false,
    ) = SignRequest(
        id = "id",
        sessionId = ByteArray(0),
        messageType = messageType,
        typeVerified = typeVerified,
        messagePreview = messagePreview,
        fromPeer = 2u,
        timestamp = 0uL,
        metadata = metadata,
    )

    @Test
    fun `the label is shown alongside the preview, not only when it is blank`() {
        // The regression this covers: the label used to be appended only if the
        // summary was otherwise empty, and the preview is never empty for a real
        // request, so the label never appeared and the prompt was a bare hash.
        val summary = request().describe()
        assertTrue("expected the label in: $summary", summary.contains("nostr-event"))
        assertTrue(
            "the label must read as asserted, not as established fact: $summary",
            summary.contains("claimed"),
        )
        assertTrue("expected the preview in: $summary", summary.contains("abcd1234abcd1234"))
    }

    @Test
    fun `a label chosen to look authoritative still reads as claimed`() {
        // The prefix is ours and comes first, so a requester cannot phrase their
        // way out of it.
        val summary = request(messageType = "verified bitcoin-sighash").describe()
        assertTrue("got: $summary", summary.startsWith("claimed: "))
    }

    @Test
    fun `a verified label carries no qualifier`() {
        // Its digest was recomputed from the supplied body and matched, so
        // calling it a claim would be wrong and would dilute the qualifier on
        // the requests that are only claims.
        val summary = request(messageType = "bitcoin-sighash", typeVerified = true).describe()
        assertTrue("got: $summary", summary.startsWith("bitcoin-sighash"))
        assertTrue("a proven label must not be marked claimed: $summary", !summary.contains("claimed"))
    }

    @Test
    fun `the qualifier is not a blanket prefix on every request`() {
        // The point of the flag: the same label reads differently depending on
        // whether anything checked it.
        val claimed = request(messageType = "bitcoin-sighash", typeVerified = false).describe()
        val proven = request(messageType = "bitcoin-sighash", typeVerified = true).describe()
        assertTrue("got: $claimed", claimed != proven)
    }

    @Test
    fun `a bitcoin request is distinguishable from a nostr one`() {
        val nostr = request(messageType = "nostr-event").describe()
        val bitcoin = request(messageType = "bitcoin-sighash").describe()
        assertTrue(nostr.contains("nostr-event"))
        assertTrue(bitcoin.contains("bitcoin-sighash"))
        assertTrue("the two must not read the same", nostr != bitcoin)
    }

    @Test
    fun `an amount still wins over everything else`() {
        // A spend with a known amount and destination is the most informative
        // thing available, so it stays the whole summary.
        val summary = request(
            metadata = SignRequestMetadata(
                eventKind = null,
                contentPreview = null,
                amountSats = 1500uL,
                destination = "bc1qexample",
            )
        ).describe()
        assertEquals("1500 sats to bc1qexample", summary)
    }

    @Test
    fun `an event kind appears with the label`() {
        val summary = request(
            metadata = SignRequestMetadata(
                eventKind = 1u,
                contentPreview = "hello",
                amountSats = null,
                destination = null,
            )
        ).describe()
        assertTrue(summary.contains("nostr-event"))
        assertTrue(summary.contains("kind 1"))
        assertTrue(summary.contains("hello"))
    }

    @Test
    fun `a blank label does not leave a dangling separator`() {
        // The core can hand back an empty label if the requester sent nothing or
        // if sanitizing removed every character.
        val summary = request(messageType = "").describe()
        assertEquals("abcd1234abcd1234", summary)
    }

    @Test
    fun `a request with nothing to show does not produce a stray separator`() {
        val summary = request(messageType = "", messagePreview = "").describe()
        assertEquals("", summary)
    }

    private val p2wpkh = "0014" + "03".repeat(20)
    private val opReturn = "6a0401010101"

    private fun spendRequest(spend: SpendSummary, typeVerified: Boolean = true) = request(
        messageType = "bitcoin-sighash",
        messagePreview = "ffeeddccbbaa9988",
        typeVerified = typeVerified,
        metadata = SignRequestMetadata(
            eventKind = null,
            contentPreview = null,
            amountSats = null,
            destination = null,
            spend = spend,
        ),
    )

    private val twoOutputs = SpendSummary(
        outputs = listOf(
            SpendOutput(amountSats = 90_000uL, address = "tb1qexample", scriptHex = p2wpkh),
            SpendOutput(amountSats = 8_500uL, address = null, scriptHex = opReturn),
        ),
        consumedSats = 100_000uL,
        feeSats = 1_500uL,
    )

    @Test
    fun `a spend lists every output, then the fee and the total`() {
        assertEquals(
            listOf(
                "bitcoin-sighash",
                "90,000 sats to tb1qexample",
                "8,500 sats to unrecognized script $opReturn",
                "Fee: 1,500 sats",
                "Total spent: 100,000 sats",
            ).joinToString("\n"),
            spendRequest(twoOutputs).describe(),
        )
    }

    @Test
    fun `an output with no address shows its whole script, marked unrecognized`() {
        val long = "51" + "ab".repeat(200)
        val spend = SpendSummary(listOf(SpendOutput(1uL, null, long)), 2uL, 1uL)
        assertTrue(spendRequest(spend).describe().contains("1 sats to unrecognized script $long\n"))
    }

    @Test
    fun `a spend with many outputs is never shortened`() {
        val outputs = (1..60).map { SpendOutput(it.toULong(), "tb1qout$it", p2wpkh) }
        val summary = spendRequest(SpendSummary(outputs, 2_000uL, 170uL)).describe()
        (1..60).forEach { assertTrue("output $it missing", summary.contains("\n$it sats to tb1qout$it\n")) }
        assertTrue(summary.endsWith("Fee: 170 sats\nTotal spent: 2,000 sats"))
    }

    @Test
    fun `no output is labeled as change`() {
        assertFalse(spendRequest(twoOutputs).describe().contains("change", ignoreCase = true))
        assertFalse(spendRequest(twoOutputs).spendOverview()!!.contains("change", ignoreCase = true))
    }

    @Test
    fun `a spend shows its fee even when a single amount is also set`() {
        val req = request(
            messageType = "bitcoin-sighash",
            metadata = SignRequestMetadata(null, null, 98_500uL, "tb1qexample", twoOutputs),
        )
        assertTrue(req.describe().contains("Fee: 1,500 sats"))
    }

    @Test
    fun `an unverified label on a spend still reads as claimed`() {
        assertTrue(spendRequest(twoOutputs, typeVerified = false).describe().startsWith("claimed: bitcoin-sighash\n"))
    }

    @Test
    fun `a bitcoin request with no spend renders as before`() {
        val summary = request(messageType = "bitcoin-sighash", typeVerified = true).describe()
        assertEquals("bitcoin-sighash · abcd1234abcd1234", summary)
        assertNull(request(messageType = "bitcoin-sighash").spendOverview())
    }

    @Test
    fun `the notification overview counts the outputs and never lists them`() {
        val overview = spendRequest(twoOutputs).spendOverview()!!
        assertEquals(
            "bitcoin-sighash\n2 outputs · fee 1,500 sats · total 100,000 sats\nOpen Keep to review every output and approve.",
            overview,
        )
        assertFalse(overview.contains("tb1qexample"))
        val one = SpendSummary(listOf(SpendOutput(99_000uL, "tb1qexample", p2wpkh)), 100_000uL, 1_000uL)
        assertTrue(spendRequest(one).spendOverview()!!.contains("1 output · fee 1,000 sats"))
    }

    @Test
    fun `a spend is never approvable from the notification`() {
        assertFalse(CosignNotifier.approvableFromNotification(spendRequest(twoOutputs)))
        assertTrue(CosignNotifier.approvableFromNotification(request(messageType = "bitcoin-sighash")))
        assertTrue(CosignNotifier.approvableFromNotification(request()))
    }

    @Test
    fun `sats are grouped in threes`() {
        assertEquals("0 sats", formatSats(0uL))
        assertEquals("999 sats", formatSats(999uL))
        assertEquals("1,000 sats", formatSats(1_000uL))
        assertEquals("2,100,000,000,000,000 sats", formatSats(2_100_000_000_000_000uL))
        assertEquals("18,446,744,073,709,551,615 sats", formatSats(ULong.MAX_VALUE))
    }
}
