package io.privkey.keep.nip55

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EventKindsTest {

    @Test
    fun `isSensitiveKind returns true for metadata kind 0`() {
        assertTrue(isSensitiveKind(0))
    }

    @Test
    fun `isSensitiveKind returns true for contacts kind 3`() {
        assertTrue(isSensitiveKind(3))
    }

    @Test
    fun `isSensitiveKind returns true for encrypted DM kind 4`() {
        assertTrue(isSensitiveKind(4))
    }

    @Test
    fun `isSensitiveKind returns true for gift wrap kind 1059`() {
        assertTrue(isSensitiveKind(1059))
    }

    @Test
    fun `isSensitiveKind returns true for report kind 1984`() {
        assertTrue(isSensitiveKind(1984))
    }

    @Test
    fun `isSensitiveKind returns true for mute list kind 10000`() {
        assertTrue(isSensitiveKind(10000))
    }

    @Test
    fun `isSensitiveKind returns true for relay list metadata kind 10002`() {
        assertTrue(isSensitiveKind(10002))
    }

    @Test
    fun `isSensitiveKind returns true for bookmark list kind 10003`() {
        assertTrue(isSensitiveKind(10003))
    }

    @Test
    fun `isSensitiveKind returns true for search relay list kind 10004`() {
        assertTrue(isSensitiveKind(10004))
    }

    @Test
    fun `isSensitiveKind returns true for blocked relays list kind 10006`() {
        assertTrue(isSensitiveKind(10006))
    }

    @Test
    fun `isSensitiveKind returns true for DM relay list kind 10050`() {
        assertTrue(isSensitiveKind(10050))
    }

    @Test
    fun `isSensitiveKind returns true for replaceable events 30000-39999`() {
        assertTrue(isSensitiveKind(30000))
        assertTrue(isSensitiveKind(30023))
        assertTrue(isSensitiveKind(35000))
        assertTrue(isSensitiveKind(39999))
    }

    @Test
    fun `isSensitiveKind returns false for regular text note kind 1`() {
        assertFalse(isSensitiveKind(1))
    }

    @Test
    fun `isSensitiveKind returns false for reaction kind 7`() {
        assertFalse(isSensitiveKind(7))
    }

    @Test
    fun `isSensitiveKind returns false for repost kind 6`() {
        assertFalse(isSensitiveKind(6))
    }

    @Test
    fun `isSensitiveKind returns false for outside replaceable range`() {
        assertFalse(isSensitiveKind(29999))
        assertFalse(isSensitiveKind(40000))
    }

    @Test
    fun `sensitiveKindWarning returns warning for sensitive kinds`() {
        assertNotNull(sensitiveKindWarning(0))
        assertNotNull(sensitiveKindWarning(3))
        assertNotNull(sensitiveKindWarning(4))
        assertNotNull(sensitiveKindWarning(1059))
        assertNotNull(sensitiveKindWarning(1984))
        assertNotNull(sensitiveKindWarning(10000))
        assertNotNull(sensitiveKindWarning(10002))
        assertNotNull(sensitiveKindWarning(10003))
        assertNotNull(sensitiveKindWarning(10004))
        assertNotNull(sensitiveKindWarning(10006))
        assertNotNull(sensitiveKindWarning(10050))
    }

    @Test
    fun `sensitiveKindWarning returns warning for replaceable events`() {
        assertNotNull(sensitiveKindWarning(30000))
        assertNotNull(sensitiveKindWarning(35000))
        assertNotNull(sensitiveKindWarning(39999))
    }

    @Test
    fun `sensitiveKindWarning returns null for non-sensitive kinds`() {
        assertNull(sensitiveKindWarning(1))
        assertNull(sensitiveKindWarning(7))
        assertNull(sensitiveKindWarning(6))
    }

    @Test
    fun `sensitiveKindWarning contains relevant info for metadata`() {
        val warning = sensitiveKindWarning(0)
        assertNotNull(warning)
        assertTrue(warning!!.contains("profile") || warning.contains("Metadata"))
    }

    @Test
    fun `sensitiveKindWarning contains relevant info for contacts`() {
        val warning = sensitiveKindWarning(3)
        assertNotNull(warning)
        assertTrue(warning!!.contains("contacts") || warning.contains("follow"))
    }

    @Test
    fun `sensitiveKindWarning contains relevant info for encrypted DM`() {
        val warning = sensitiveKindWarning(4)
        assertNotNull(warning)
        assertTrue(warning!!.contains("private") || warning.contains("Encrypted"))
    }
}
