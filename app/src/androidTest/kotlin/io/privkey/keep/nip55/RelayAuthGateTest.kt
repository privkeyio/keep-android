package io.privkey.keep.nip55

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.storage.RelayAuthWhitelistStore
import io.privkey.keep.uniffi.Nip55RelayAuthGate
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RelayAuthGateTest {

    private val event22242 =
        """{"kind":22242,"tags":[["relay","wss://relay.example.com/"],["challenge","abc"]]}"""
    private val eventNoRelay =
        """{"kind":22242,"tags":[["challenge","abc"]]}"""

    private lateinit var store: RelayAuthWhitelistStore

    @Before
    fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        store = RelayAuthWhitelistStore(context)
        clear()
    }

    @After
    fun teardown() {
        clear()
    }

    private fun clear() {
        store.getHosts().forEach { store.remove(it) }
    }

    @Test
    fun nullStoreDefers() {
        val (gate, host) = evaluateRelayAuthGate(null, event22242)
        assertEquals(Nip55RelayAuthGate.DEFER, gate)
        assertEquals("relay.example.com", host)
    }

    @Test
    fun emptyWhitelistDefers() {
        val (gate, _) = evaluateRelayAuthGate(store, event22242)
        assertEquals(Nip55RelayAuthGate.DEFER, gate)
    }

    @Test
    fun whitelistedRelayAutoAccepts() {
        store.add("relay.example.com")
        val (gate, host) = evaluateRelayAuthGate(store, event22242)
        assertEquals(Nip55RelayAuthGate.AUTO_ACCEPT, gate)
        assertEquals("relay.example.com", host)
    }

    @Test
    fun nonWhitelistedRelayAutoRejects() {
        store.add("other.example.com")
        val (gate, _) = evaluateRelayAuthGate(store, event22242)
        assertEquals(Nip55RelayAuthGate.AUTO_REJECT, gate)
    }

    @Test
    fun unextractableRelayWithNonEmptyWhitelistAutoRejects() {
        store.add("relay.example.com")
        val (gate, host) = evaluateRelayAuthGate(store, eventNoRelay)
        assertEquals(Nip55RelayAuthGate.AUTO_REJECT, gate)
        assertEquals(null, host)
    }
}
