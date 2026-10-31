package io.privkey.keep

import io.privkey.keep.uniffi.RelayConfigInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * When the relays card offers to reset the relay config. Only a failed read of an
 * account's record is a fault the core can reset; everything else shows as it reads.
 */
class ReadRelayConfigTest {

    @Test
    fun aReadableConfigIsShownAndNotOffered() {
        val read = readRelayConfig(KEY) { CONFIG }
        assertEquals(CONFIG, read.config)
        assertFalse(read.unreadable)
    }

    @Test
    fun aFailedReadForTheActiveAccountIsUnreadable() {
        val read = readRelayConfig(KEY) { error("corrupt") }
        assertTrue(read.unreadable)
        assertEquals(EMPTY, read.config)
    }

    @Test
    fun aFailedReadWithNoActiveAccountIsNotOffered() {
        val read = readRelayConfig(null) { error("corrupt") }
        assertFalse(read.unreadable)
        assertEquals(EMPTY, read.config)
    }

    @Test
    fun theActiveKeyIsWhatIsRead() {
        var asked: String? = "unset"
        readRelayConfig(KEY) { asked = it; CONFIG }
        assertEquals(KEY, asked)
    }

    private companion object {
        val KEY = "aa".repeat(32)
        val CONFIG = RelayConfigInfo(listOf("wss://relay.example.com/"), listOf("wss://profile.example.com/"), emptyList())
        val EMPTY = RelayConfigInfo(emptyList(), emptyList(), emptyList())
    }
}
