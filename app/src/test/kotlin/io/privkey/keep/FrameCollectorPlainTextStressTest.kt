package io.privkey.keep

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FrameCollectorPlainTextStressTest {

    private val nostrconnectValidator: (String) -> Boolean = { it.startsWith("nostrconnect://") }

    @Test
    fun whitespaceBeforeABraceStillTakesTheJsonPath() {
        assertNull(FrameCollector().processQrContent("  \n\t{\"unknown\":1}"))
        assertNull(FrameCollector().processQrContent(" {not json"))
        val share = """ {"version":1,"encrypted_share":"x"}"""
        assertEquals(share.trim(), FrameCollector().processQrContent(share))
    }

    @Test
    fun theLengthCapIsInclusiveAt4096() {
        val at = "nostrconnect://" + "a".repeat(4096 - 15)
        assertEquals(4096, at.length)
        assertEquals(at, FrameCollector().processQrContent(at))
        assertNull(FrameCollector().processQrContent(at + "a"))
        assertEquals(at, FrameCollector().processQrContent("   $at   "))
    }

    @Test
    fun nulBytesAreNotTrimmedByKotlinTrim() {
        val uri = "nostrconnect://" + "a".repeat(64) + "?relay=wss://r.example&secret=s"
        val leading = FrameCollector().processQrContent("\u0000$uri")
        assertEquals("\u0000$uri", leading)
        assertTrue(!nostrconnectValidator(leading!!))
        val trailing = FrameCollector().processQrContent("$uri\u0000")
        assertEquals("$uri\u0000", trailing)
        assertTrue(nostrconnectValidator(trailing!!))
        assertEquals("\u0000", FrameCollector().processQrContent("\u0000"))
    }

    @Test
    fun emptyAndNonJsonPlainTextAreReturned() {
        assertEquals("", FrameCollector().processQrContent("   "))
        assertEquals("[1,2]", FrameCollector().processQrContent("[1,2]"))
        assertEquals("\u202Enostrconnect://", FrameCollector().processQrContent("\u202Enostrconnect://"))
    }

    @Test
    fun plainTextDuringAnAnimatedCollectionLeavesItIntact() {
        val c = FrameCollector()
        assertNull(c.processQrContent("""{"f":0,"t":2,"d":"x"}"""))
        assertEquals("nostrconnect://x", c.processQrContent("nostrconnect://x"))
        assertTrue(c.isCollecting)
        assertEquals(1, c.framesCollected)
    }

    @Test
    fun deeplyNestedJsonDoesNotCrash() {
        assertNull(FrameCollector().processQrContent("{\"a\":" + "[".repeat(4000)))
    }
}
