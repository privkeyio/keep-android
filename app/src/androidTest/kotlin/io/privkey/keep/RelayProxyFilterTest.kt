package io.privkey.keep

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

// Under a proxy the relay names must reach the proxy unresolved: a name that does not
// resolve locally (an onion address, or a reserved .invalid name here) is kept, while a
// literal internal host is still refused without any lookup.
@RunWith(AndroidJUnit4::class)
class RelayProxyFilterTest {

    @Test
    fun keepsNamesThatDoNotResolveLocally() {
        val relays = listOf(
            "wss://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion",
            "wss://relay.nonexistent.invalid"
        )
        assertEquals(relays, filterRelaysForProxy(relays))
        assertEquals(emptyList<String>(), filterRelaysPreConnection(relays))
    }

    @Test
    fun refusesLiteralInternalHosts() {
        val relays = listOf(
            "wss://localhost",
            "wss://127.0.0.1",
            "wss://10.0.0.1:443",
            "wss://192.168.1.1",
            "wss://8.8.8.8"
        )
        assertEquals(listOf("wss://8.8.8.8"), filterRelaysForProxy(relays))
    }
}
