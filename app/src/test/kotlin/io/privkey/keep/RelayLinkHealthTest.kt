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
}
