package io.privkey.keep

import io.privkey.keep.uniffi.RelayConfigInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * When the relays card offers to reset the relay config, and when the reset runs. Only a failed read of an
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

    @Test
    fun aRecordThatStillFailsTwiceIsReset() {
        val reset = mutableListOf<String>()
        var reads = 0
        assertTrue(resetIfStillUnreadable(KEY, KEY, read = { reads++; error("corrupt") }, reset = { reset += it }))
        assertEquals(2, reads)
        assertEquals(listOf(KEY), reset)
    }

    @Test
    fun aRecordThatReadsAgainIsKept() {
        var reads = 0
        var reset = false
        val ran = resetIfStillUnreadable(
            KEY, KEY,
            read = { if (++reads == 1) error("transient") },
            reset = { reset = true }
        )
        assertFalse(ran)
        assertFalse(reset)
    }

    @Test
    fun anotherActiveAccountIsNeverReset() {
        var touched = false
        assertThrows(IllegalStateException::class.java) {
            resetIfStillUnreadable(KEY, OTHER, read = { touched = true }, reset = { touched = true })
        }
        assertFalse(touched)
    }

    @Test
    fun noActiveAccountIsNeverReset() {
        var touched = false
        assertThrows(IllegalStateException::class.java) {
            resetIfStillUnreadable(KEY, null, read = { touched = true }, reset = { touched = true })
        }
        assertFalse(touched)
    }

    private companion object {
        val KEY = "aa".repeat(32)
        val OTHER = "bb".repeat(32)
        val CONFIG = RelayConfigInfo(listOf("wss://relay.example.com/"), listOf("wss://profile.example.com/"), emptyList())
        val EMPTY = RelayConfigInfo(emptyList(), emptyList(), emptyList())
    }
}
