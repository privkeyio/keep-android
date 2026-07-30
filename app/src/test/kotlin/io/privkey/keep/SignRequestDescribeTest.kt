package io.privkey.keep

import io.privkey.keep.uniffi.SignRequest
import io.privkey.keep.uniffi.SignRequestMetadata
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
}
