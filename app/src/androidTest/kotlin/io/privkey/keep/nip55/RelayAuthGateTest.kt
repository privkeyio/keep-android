package io.privkey.keep.nip55

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.storage.RelayAuthWhitelistStore
import io.privkey.keep.storage.corruptStoredValue
import io.privkey.keep.storage.forgetWriteProbe
import io.privkey.keep.storage.writeAndFindStoredName
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
        // Cleared before the store is built, not after: deleting the file under a
        // live SharedPreferences instance leaves that instance able to write its
        // cached contents back.
        clear()
        store = RelayAuthWhitelistStore(context())
    }

    @After
    fun teardown() {
        clear()
    }

    private fun clear() {
        // Not through hosts(): a test that stages an unreadable list would make
        // the teardown raise and report as the failure instead of the test.
        context().deleteSharedPreferences(WHITELIST_PREFS)
    }

    private fun context(): Context = ApplicationProvider.getApplicationContext()

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

    /**
     * The gate's documented fail-closed leg, for the fault that used to miss it.
     *
     * It was a `catch`, so it covered only the fault that raises. A value that
     * would not decrypt came back as an empty set, took the "deliberately empty"
     * leg, and deferred to per-app grant resolution: the gate came off, and a
     * grant given earlier could auto-approve a relay this list was excluding,
     * with nothing raised or logged.
     *
     * Staged on disk rather than injected, so what is asserted is the behavior
     * for a real undecryptable entry.
     */
    @Test
    fun aWhitelistThatCannotBeReadAutoRejects() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val storedName = writeAndFindStoredName(context, WHITELIST_PREFS) {
            store.add("relay.example.com")
        }
        corruptStoredValue(context, WHITELIST_PREFS, storedName)

        // A fresh store, since the readable value may be cached in the instance
        // that wrote it.
        val (gate, host) = evaluateRelayAuthGate(RelayAuthWhitelistStore(context), event22242)

        assertEquals(
            "an unreadable whitelist must not read as no whitelist",
            Nip55RelayAuthGate.AUTO_REJECT,
            gate
        )
        assertEquals("relay.example.com", host)
        forgetWriteProbe(context, WHITELIST_PREFS)
    }

    // The same relay, listed and readable, is accepted. Without this the test
    // above could pass on a gate that rejected everything.
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

    private companion object {
        const val WHITELIST_PREFS = "keep_relay_auth_whitelist"
    }
}
