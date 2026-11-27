package io.privkey.keep

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

// Plain-text codes used to be dropped before the scanner's validator ran, so the nsec,
// approver pairing and nostrconnect scanners could never accept a scan.
class FrameCollectorPlainTextTest {

    @Test
    fun plainTextCodesReachTheValidator() {
        val collector = FrameCollector()
        val uri = "nostrconnect://${"a".repeat(64)}?relay=wss%3A%2F%2Frelay.example.com&secret=0123456789abcdef"
        assertEquals(uri, collector.processQrContent("  $uri\n"))
        assertEquals("keep-approver:v1?x=1", collector.processQrContent("keep-approver:v1?x=1"))
    }

    @Test
    fun anOverLongPlainTextCodeIsStillDropped() {
        assertNull(FrameCollector().processQrContent("n".repeat(4097)))
    }

    @Test
    fun aJsonObjectOfNoKnownShapeIsStillDropped() {
        assertNull(FrameCollector().processQrContent("""{"unknown":1}"""))
    }
}
