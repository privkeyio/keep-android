package io.privkey.keep

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RelayLinkHealthTest {

    @Test
    fun normalizeStripsSlashCaseAndDefaultPort() {
        assertEquals(
            "wss://relay.example.com",
            normalizeRelayUrl("wss://Relay.Example.com:443/"),
        )
        assertEquals(
            "wss://relay.example.com",
            normalizeRelayUrl("wss://relay.example.com"),
        )
        assertEquals(
            "wss://relay.example.com/path",
            normalizeRelayUrl("wss://relay.example.com/path/"),
        )
        assertEquals("wss://relay.example.com", normalizeRelayUrl("relay.example.com"))
        assertEquals("ws://relay.example.com", normalizeRelayUrl("ws://relay.example.com:80"))
        assertEquals(
            "wss://relay.example.com",
            normalizeRelayUrl("wss://relay.example.com:0443"),
        )
        assertEquals(
            "wss://relay.example.com:8443",
            normalizeRelayUrl("wss://relay.example.com:8443"),
        )
    }

    @Test
    fun lookupMatchesConfiguredStringToCoreUrl() {
        val links = listOf(
            RelayLinkHealth(
                url = "wss://relay.example.com",
                status = RelayLinkStatus.CONNECTED,
                lastConnectedMs = 0,
                rttMs = 42,
            )
        )
        assertEquals(
            RelayLinkStatus.CONNECTED,
            relayLinkFor("wss://relay.example.com/", links)?.status,
        )
        assertNull(relayLinkFor("wss://other.example", links))
    }

    @Test
    fun normalizeMatchesReachableCoreSpellings() {
        assertEquals(
            "wss://relay.example.com:8443",
            normalizeRelayUrl("wss://relay.example.com:08443"),
        )
        assertEquals(
            "wss://relay.example.com:80",
            normalizeRelayUrl("wss://relay.example.com:00080/"),
        )
        assertEquals(
            "wss://relay.example.com:4430",
            normalizeRelayUrl("wss://relay.example.com:4430"),
        )
        assertEquals(
            "wss://relay.example.com/bar",
            normalizeRelayUrl("wss://relay.example.com/foo/../bar"),
        )
        assertEquals(
            "wss://relay.example.com/bar",
            normalizeRelayUrl("wss://relay.example.com/./bar/"),
        )
        assertEquals(
            "wss://relay.example.com",
            normalizeRelayUrl("wss://relay.example.com/foo/.."),
        )
        assertEquals(
            "wss://example.com/Bar",
            normalizeRelayUrl("wss://EXAMPLE.com/Foo/../Bar/"),
        )
        assertEquals(
            "wss://relay.example.com//foo",
            normalizeRelayUrl("wss://relay.example.com//foo"),
        )
        assertEquals(
            "wss://relay.example.com/?q=a%27b",
            normalizeRelayUrl("wss://relay.example.com/?q=a'b"),
        )
        assertEquals(
            "wss://relay.example.com/?q=a%27b",
            normalizeRelayUrl("wss://relay.example.com/?q=a'b/"),
        )
        assertEquals(
            "wss://relay.example.com/a'b",
            normalizeRelayUrl("wss://relay.example.com/a'b"),
        )
        assertEquals(
            "wss://relay.example.com/#c'd",
            normalizeRelayUrl("wss://relay.example.com/#c'd"),
        )
        assertEquals(
            "wss://relay.example.com/a'b?q=c%27d#e'f",
            normalizeRelayUrl("wss://relay.example.com/a'b?q=c'd#e'f"),
        )
        assertEquals(
            "wss://relay.example.com/?q=../a",
            normalizeRelayUrl("wss://relay.example.com/?q=../a"),
        )
        assertEquals(
            "wss://relay.example.com/foo/?q=1",
            normalizeRelayUrl("wss://relay.example.com/foo/?q=1"),
        )
    }

    @Test
    fun lookupMatchesCoreCanonicalUrl() {
        val links = listOf(
            RelayLinkHealth(
                url = "wss://relay.example.com:8443",
                status = RelayLinkStatus.CONNECTED,
                lastConnectedMs = 0,
                rttMs = 12,
            ),
            RelayLinkHealth(
                url = "wss://relay.example.com/bar",
                status = RelayLinkStatus.CONNECTING,
                lastConnectedMs = 0,
                rttMs = null,
            ),
            RelayLinkHealth(
                url = "wss://relay.example.com/?q=a%27b",
                status = RelayLinkStatus.OFFLINE,
                lastConnectedMs = 1_700_000_000_000,
                rttMs = null,
            ),
        )
        assertEquals(
            RelayLinkStatus.CONNECTED,
            relayLinkFor("wss://relay.example.com:08443/", links)?.status,
        )
        assertEquals(
            RelayLinkStatus.CONNECTING,
            relayLinkFor("wss://Relay.Example.com/foo/../bar/", links)?.status,
        )
        assertEquals(
            RelayLinkStatus.OFFLINE,
            relayLinkFor("wss://relay.example.com/?q=a'b", links)?.status,
        )
    }
}
