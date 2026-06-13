package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RelayAuthWhitelistStoreIntegrationTest {

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
    fun normalizesThenDedupes() {
        assertEquals("relay.example.com", store.add("wss://Relay.Example.com/"))
        // Same host after normalization (scheme/case/trailing slash) must not duplicate.
        assertEquals("relay.example.com", store.add("relay.example.com"))
        assertEquals("relay.example.com", store.add("ws://relay.example.com:80"))

        assertEquals(listOf("relay.example.com"), store.getHosts())
    }

    @Test
    fun rejectsUnnormalizableInput() {
        assertNull(store.add("   "))
        assertNull(store.add(""))
        assertTrue(store.getHosts().isEmpty())
    }

    @Test
    fun maxEntriesRejectsOnlyNewHostsAtCap() {
        repeat(256) { i ->
            assertNotNull(store.add("relay$i.example.com"))
        }
        assertEquals(256, store.getHosts().size)

        // A brand-new host at the cap is rejected.
        assertNull(store.add("overflow.example.com"))
        assertFalse(store.getHosts().contains("overflow.example.com"))

        // Re-adding an existing host at the cap is still allowed (idempotent).
        assertEquals("relay0.example.com", store.add("relay0.example.com"))
        assertEquals(256, store.getHosts().size)
    }

    @Test
    fun removeDeletesEntry() {
        assertEquals("relay.example.com", store.add("relay.example.com"))
        assertTrue(store.getHosts().contains("relay.example.com"))

        store.remove("relay.example.com")
        assertFalse(store.getHosts().contains("relay.example.com"))

        // Removing a non-existent host is a no-op.
        store.remove("relay.example.com")
        assertTrue(store.getHosts().isEmpty())
    }
}
