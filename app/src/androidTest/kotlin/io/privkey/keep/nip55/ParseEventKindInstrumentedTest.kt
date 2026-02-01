package io.privkey.keep.nip55

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ParseEventKindInstrumentedTest {

    @Test
    fun parseEventKindExtractsKindFromValidJson() {
        val json = """{"kind":1,"content":"hello","pubkey":"abc123"}"""
        assertEquals(1, parseEventKind(json))
    }

    @Test
    fun parseEventKindHandlesKind0() {
        val json = """{"kind":0,"content":""}"""
        assertEquals(0, parseEventKind(json))
    }

    @Test
    fun parseEventKindHandlesLargeKindValues() {
        val json = """{"kind":30023,"content":""}"""
        assertEquals(30023, parseEventKind(json))
    }

    @Test
    fun parseEventKindHandlesMaxValidKind() {
        val json = """{"kind":65535,"content":""}"""
        assertEquals(65535, parseEventKind(json))
    }

    @Test
    fun parseEventKindReturnsNullForKindAboveMax() {
        val json = """{"kind":65536,"content":""}"""
        assertNull(parseEventKind(json))
    }

    @Test
    fun parseEventKindReturnsNullForNegativeKind() {
        val json = """{"kind":-1,"content":""}"""
        assertNull(parseEventKind(json))
    }

    @Test
    fun parseEventKindReturnsNullForMissingKind() {
        val json = """{"content":"hello","pubkey":"abc123"}"""
        assertNull(parseEventKind(json))
    }

    @Test
    fun parseEventKindReturnsNullForInvalidJson() {
        assertNull(parseEventKind("not json"))
        assertNull(parseEventKind(""))
        assertNull(parseEventKind("{"))
    }

    @Test
    fun parseEventKindReturnsNullForKindAsString() {
        val json = """{"kind":"1","content":""}"""
        assertNull(parseEventKind(json))
    }

    @Test
    fun parseEventKindHandlesComplexValidEvent() {
        val json = """
            {
                "kind": 1,
                "pubkey": "npub1...",
                "created_at": 1234567890,
                "tags": [["p", "abc123"]],
                "content": "Hello World"
            }
        """.trimIndent()
        assertEquals(1, parseEventKind(json))
    }
}
