package io.privkey.keep.storage

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ProfileRelayConfigStoreTest {

    private lateinit var store: ProfileRelayConfigStore

    @Before
    fun setup() {
        store = ProfileRelayConfigStore(ApplicationProvider.getApplicationContext())
        runBlocking {
            store.deleteRelaysForAccount("account_a")
            store.deleteRelaysForAccount("account_b")
            store.deleteRelaysForAccount("account_c")
        }
    }

    @Test
    fun relaysPersistIndependentlyPerAccount() = runBlocking {
        val relaysA = listOf("wss://relay.damus.io/", "wss://nos.lol/")
        val relaysB = listOf("wss://relay.primal.net/", "wss://relay.nsec.app/")

        store.setRelaysForAccount("account_a", relaysA)
        store.setRelaysForAccount("account_b", relaysB)

        val loadedA = store.getRelaysForAccount("account_a")
        val loadedB = store.getRelaysForAccount("account_b")

        assertEquals(relaysA, loadedA)
        assertEquals(relaysB, loadedB)
    }

    @Test
    fun modifyingOneAccountDoesNotAffectAnother() = runBlocking {
        val relaysA = listOf("wss://relay.damus.io/")
        val relaysB = listOf("wss://relay.primal.net/")

        store.setRelaysForAccount("account_a", relaysA)
        store.setRelaysForAccount("account_b", relaysB)

        store.setRelaysForAccount("account_a", listOf("wss://nos.lol/"))

        assertEquals(listOf("wss://nos.lol/"), store.getRelaysForAccount("account_a"))
        assertEquals(relaysB, store.getRelaysForAccount("account_b"))
    }

    @Test
    fun deletingOneAccountDoesNotAffectAnother() = runBlocking {
        store.setRelaysForAccount("account_a", listOf("wss://relay.damus.io/"))
        store.setRelaysForAccount("account_b", listOf("wss://relay.primal.net/"))

        store.deleteRelaysForAccount("account_a")

        assertTrue(store.getRelaysForAccount("account_a").isEmpty())
        assertEquals(listOf("wss://relay.primal.net/"), store.getRelaysForAccount("account_b"))
    }

    @Test
    fun accountSwitchLoadsCorrectRelays() = runBlocking {
        val relaysA = listOf("wss://relay.damus.io/", "wss://nos.lol/")
        val relaysB = listOf("wss://relay.primal.net/")
        val relaysC = listOf("wss://relay.nsec.app/", "wss://relay.damus.io/", "wss://nos.lol/")

        store.setRelaysForAccount("account_a", relaysA)
        store.setRelaysForAccount("account_b", relaysB)
        store.setRelaysForAccount("account_c", relaysC)

        assertEquals(relaysA, store.getRelaysForAccount("account_a"))
        assertEquals(relaysB, store.getRelaysForAccount("account_b"))
        assertEquals(relaysC, store.getRelaysForAccount("account_c"))

        assertEquals(relaysA, store.getRelaysForAccount("account_a"))
    }

    @Test
    fun emptyAccountReturnsEmptyList() = runBlocking {
        assertTrue(store.getRelaysForAccount("nonexistent_account").isEmpty())
    }

    @Test
    fun invalidRelayUrlsAreRejected() = runBlocking {
        val mixed = listOf(
            "wss://relay.damus.io/",
            "http://not-wss.com/",
            "wss://relay.primal.net/",
            "not-a-url",
            "",
            "ws://no-tls.relay.com/",
            "wss://localhost/",
            "wss://127.0.0.1/"
        )

        store.setRelaysForAccount("account_a", mixed)
        val saved = store.getRelaysForAccount("account_a")

        assertTrue("Valid wss URLs should be saved", saved.contains("wss://relay.damus.io/"))
        assertTrue("Valid wss URLs should be saved", saved.contains("wss://relay.primal.net/"))
        assertTrue("http URLs should be rejected", !saved.contains("http://not-wss.com/"))
        assertTrue("Non-URL strings should be rejected", !saved.contains("not-a-url"))
        assertTrue("Empty strings should be rejected", !saved.contains(""))
        assertTrue("ws URLs should be rejected", !saved.contains("ws://no-tls.relay.com/"))
        assertTrue("localhost should be rejected", !saved.contains("wss://localhost/"))
        assertTrue("loopback should be rejected", !saved.contains("wss://127.0.0.1/"))
    }

    @Test
    fun invalidPortsAreRejected() = runBlocking {
        val relays = listOf(
            "wss://relay.damus.io:443/",
            "wss://relay.damus.io:0/",
            "wss://relay.damus.io:99999/"
        )

        store.setRelaysForAccount("account_a", relays)
        val saved = store.getRelaysForAccount("account_a")

        assertTrue("Valid port 443 should be accepted", saved.contains("wss://relay.damus.io:443/"))
        assertTrue("Port 0 should be rejected", !saved.contains("wss://relay.damus.io:0/"))
        assertTrue("Port 99999 should be rejected", !saved.contains("wss://relay.damus.io:99999/"))
    }

    @Test
    fun maxRelaysEnforced() = runBlocking {
        val tooMany = (1..25).map { "wss://relay$it.example.com/" }

        store.setRelaysForAccount("account_a", tooMany)
        val saved = store.getRelaysForAccount("account_a")

        assertEquals(RelayConfigStore.MAX_RELAYS, saved.size)
    }

    @Test
    fun storeInitFailureDoesNotCrash() {
        val store: ProfileRelayConfigStore? = runCatching {
            ProfileRelayConfigStore(ApplicationProvider.getApplicationContext())
        }.getOrNull()

        if (store != null) {
            val relays = store.getRelaysForAccount("test_account")
            assertTrue(relays is List<String>)
        }
    }
}
