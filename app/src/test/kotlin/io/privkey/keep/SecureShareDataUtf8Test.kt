package io.privkey.keep

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Coverage for [SecureShareData.toUtf8Bytes]. Secrets (e.g. an imported nsec) now
 * cross the UniFFI boundary as this ByteArray instead of an immutable String, so
 * the encoding MUST equal what `String(chars).toByteArray()` produced, or the
 * decoded value on the Rust side would differ from what the user entered.
 */
class SecureShareDataUtf8Test {

    private fun data(value: String) = SecureShareData(4096).apply { update(value) }

    @Test
    fun asciiEncodingMatchesStringUtf8() {
        val value = "nsec1qqqqqqqqqqqqqqqqqqqqqqq"
        assertArrayEquals(value.toByteArray(Charsets.UTF_8), data(value).toUtf8Bytes())
    }

    @Test
    fun multiByteEncodingMatchesStringUtf8() {
        val value = "wörds with 🔑 and münchen"
        assertArrayEquals(value.toByteArray(Charsets.UTF_8), data(value).toUtf8Bytes())
    }

    @Test
    fun returnedArrayIsAnIndependentCopy() {
        val d = data("nsec1testtesttest")
        d.toUtf8Bytes().fill(0)
        assertArrayEquals("nsec1testtesttest".toByteArray(Charsets.UTF_8), d.toUtf8Bytes())
    }

    @Test
    fun clearedEncodesToEmpty() {
        val d = data("nsec1testtesttest")
        d.clear()
        assertTrue(d.toUtf8Bytes().isEmpty())
    }
}
