package io.privkey.keep.nip46

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The NIP-98 HTTP-auth rows must be gated on presence, not field content, so a
 * malformed kind-27235 (present httpAuth but no `u` tag) still flags the missing
 * target rather than hiding it. Assertions check row count + values (independent
 * of resource-id resolution in JVM unit tests).
 */
class HttpAuthRowsTest {
    private val unspecified = "Unspecified"

    @Test
    fun noHttpAuth_yieldsNoRows() {
        assertTrue(httpAuthRows(hasHttpAuth = false, url = "https://x", method = "GET", unspecified).isEmpty())
    }

    @Test
    fun presentButBothBlank_stillShowsBothRowsAsUnspecified() {
        val rows = httpAuthRows(hasHttpAuth = true, url = null, method = "", unspecified)
        assertEquals(2, rows.size)
        assertEquals(unspecified, rows[0].second)
        assertEquals(unspecified, rows[1].second)
    }

    @Test
    fun presentWithValues_showsValues() {
        val rows = httpAuthRows(hasHttpAuth = true, url = "https://api.example.com/x", method = "POST", unspecified)
        assertEquals(2, rows.size)
        assertEquals("https://api.example.com/x", rows[0].second)
        assertEquals("POST", rows[1].second)
    }

    @Test
    fun oneBlank_fallsBackForThatFieldOnly() {
        val rows = httpAuthRows(hasHttpAuth = true, url = "https://x", method = null, unspecified)
        assertEquals("https://x", rows[0].second)
        assertEquals(unspecified, rows[1].second)
    }
}
