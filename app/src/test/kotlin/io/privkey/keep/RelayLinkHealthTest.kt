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
    fun normalizeCanonicalizesDottedIpv4() {
        assertEquals("wss://1.2.3.4", normalizeRelayUrl("wss://1.2.3.004"))
        assertEquals("wss://1.2.3.4", normalizeRelayUrl("wss://001.2.3.4"))
        assertEquals("wss://1.2.3.4", normalizeRelayUrl("wss://01.02.03.04/"))
        assertEquals("wss://1.2.3.8", normalizeRelayUrl("wss://1.2.3.010"))
        assertEquals("wss://1.2.3.8", normalizeRelayUrl("wss://1.2.3.00010"))
        assertEquals("wss://1.2.3.0", normalizeRelayUrl("wss://1.2.3.00"))
        assertEquals("wss://11.0.0.1:8443", normalizeRelayUrl("wss://11.0.0.001:08443"))
        assertEquals("wss://1.2.3.4", normalizeRelayUrl("wss://001.2.3.4:0443/"))
        assertEquals("wss://1.2.3.8/bar", normalizeRelayUrl("wss://1.2.3.010/foo/../bar"))
        assertEquals("wss://1.2.3.4/?q=a%27b", normalizeRelayUrl("wss://1.2.3.004/?q=a'b"))
        assertEquals("wss://8.8.8.8", normalizeRelayUrl("wss://8.8.8.8"))
        assertEquals("wss://1.2.3.4", normalizeRelayUrl("wss://1.2.3.4"))
        assertEquals("wss://1.2.3.08", normalizeRelayUrl("wss://1.2.3.08"))
        assertEquals("wss://9.9.9.009", normalizeRelayUrl("wss://9.9.9.009"))
        assertEquals("wss://08.8.8.8", normalizeRelayUrl("wss://08.8.8.8"))
        assertEquals("wss://256.1.1.1", normalizeRelayUrl("wss://256.1.1.1"))
        assertEquals("wss://relay.example.com:", normalizeRelayUrl("wss://relay.example.com:"))
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
            RelayLinkHealth(
                url = "wss://1.2.3.8",
                status = RelayLinkStatus.CONNECTED,
                lastConnectedMs = 0,
                rttMs = 7,
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
        assertEquals(
            RelayLinkStatus.CONNECTED,
            relayLinkFor("wss://1.2.3.010/", links)?.status,
        )
        assertNull(relayLinkFor("wss://1.2.3.08", links))
    }
}
