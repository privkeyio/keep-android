package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RelayAuthWhitelistStoreIntegrationTest {

    private lateinit var store: RelayAuthWhitelistStore

    @Before
    fun setup() {
        // Cleared before the store is built, not after: deleting the file under a
        // live SharedPreferences instance leaves that instance able to write its
        // cached contents back.
        clear()
        store = RelayAuthWhitelistStore(ApplicationProvider.getApplicationContext())
    }

    @After
    fun teardown() {
        clear()
    }

    private fun clear() {
        // The whole file, rather than removing the hosts one at a time. A host-by-host
        // clear reads first, and hosts() raises on a fault, so a file another class
        // left unreadable would fail every test here in setup rather than being
        // recovered. The old read answered an empty list and self-healed by accident.
        ApplicationProvider.getApplicationContext<Context>()
            .deleteSharedPreferences(RelayAuthWhitelistStore.PREFS_NAME)
    }

    @Test
    fun normalizesThenDedupes() {
        assertEquals(RelayAuthWhitelistStore.AddResult.Added("relay.example.com"), store.add("wss://Relay.Example.com/"))
        // Same host after normalization (scheme/case/trailing slash) must not duplicate.
        assertEquals(RelayAuthWhitelistStore.AddResult.Added("relay.example.com"), store.add("relay.example.com"))
        assertEquals(RelayAuthWhitelistStore.AddResult.Added("relay.example.com"), store.add("ws://relay.example.com:80"))

        assertEquals(listOf("relay.example.com"), store.hosts())
    }

    @Test
    fun rejectsUnnormalizableInput() {
        assertEquals(RelayAuthWhitelistStore.AddResult.InvalidHost, store.add("   "))
        assertEquals(RelayAuthWhitelistStore.AddResult.InvalidHost, store.add(""))
        assertTrue(store.hosts().isEmpty())
    }

    @Test
    fun maxEntriesRejectsOnlyNewHostsAtCap() {
        repeat(256) { i ->
            assertTrue(store.add("relay$i.example.com") is RelayAuthWhitelistStore.AddResult.Added)
        }
        assertEquals(256, store.hosts().size)

        // A brand-new host at the cap is rejected.
        assertEquals(RelayAuthWhitelistStore.AddResult.Full, store.add("overflow.example.com"))
        assertFalse(store.hosts().contains("overflow.example.com"))

        // Re-adding an existing host at the cap is still allowed (idempotent).
        assertEquals(RelayAuthWhitelistStore.AddResult.Added("relay0.example.com"), store.add("relay0.example.com"))
        assertEquals(256, store.hosts().size)
    }

    @Test
    fun removeDeletesEntry() {
        assertEquals(RelayAuthWhitelistStore.AddResult.Added("relay.example.com"), store.add("relay.example.com"))
        assertTrue(store.hosts().contains("relay.example.com"))

        store.remove("relay.example.com")
        assertFalse(store.hosts().contains("relay.example.com"))

        // Removing a non-existent host is a no-op.
        store.remove("relay.example.com")
        assertTrue(store.hosts().isEmpty())
    }
}
