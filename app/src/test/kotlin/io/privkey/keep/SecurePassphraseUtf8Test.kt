package io.privkey.keep

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Coverage for [SecurePassphrase.toUtf8Bytes]. The
 * ncryptsec export password now crosses the UniFFI boundary as this ByteArray
 * instead of an immutable String, so the encoding MUST match what the old
 * `String(chars).toByteArray()` path produced, or a user's password would be
 * silently altered and the ncryptsec would be undecryptable with what they typed.
 */
class SecurePassphraseUtf8Test {

    private fun passphrase(value: String) = SecurePassphrase().apply { update(value) }

    @Test
    fun asciiEncodingMatchesStringUtf8() {
        val value = "correct horse battery"
        assertArrayEquals(value.toByteArray(Charsets.UTF_8), passphrase(value).toUtf8Bytes())
    }

    @Test
    fun multiByteEncodingMatchesStringUtf8() {
        // Umlauts (2-byte) + an emoji (surrogate pair, 4-byte) exercise the paths
        // where a naive char-to-byte cast would diverge from real UTF-8.
        val value = "pässwörd-🔑"
        assertArrayEquals(value.toByteArray(Charsets.UTF_8), passphrase(value).toUtf8Bytes())
    }

    @Test
    fun returnedArrayIsAnIndependentCopy() {
        val p = passphrase("correct horse battery")
        val first = p.toUtf8Bytes()
        first.fill(0)
        assertArrayEquals("correct horse battery".toByteArray(Charsets.UTF_8), p.toUtf8Bytes())
    }

    @Test
    fun clearedPassphraseEncodesToEmpty() {
        val p = passphrase("correct horse battery")
        p.clear()
        assertTrue(p.toUtf8Bytes().isEmpty())
    }
}
