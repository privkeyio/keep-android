package io.privkey.keep.nip46

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

class NostrConnectInputStressTest {

    // char::is_whitespace for every code point, printed by rustc 1.x from (0..=0x10FFFF).
    private val rustWhitespace = listOf(
        0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x0020, 0x0085, 0x00A0, 0x1680,
        0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
        0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
    ).map { it.toChar() }.toSet()

    private val grantable = setOf(
        "sign_event", "nip04_encrypt", "nip04_decrypt", "nip44_encrypt", "nip44_decrypt",
        "nip44v3_encrypt", "nip44v3_decrypt",
    )

    @Test
    fun theTrimMatchesRustsWhitespaceForEveryBmpChar() {
        val wrong = mutableListOf<String>()
        for (code in 0..0xFFFF) {
            val c = code.toChar()
            if (c.isSurrogate() || c == ',') continue
            val isWs = c in rustWhitespace
            val offered = offeredNostrconnectMethods("${c}nip04_encrypt$c")
            if ((offered == listOf("nip04_encrypt")) != isWs) wrong += "U+%04X offered=%s".format(code, offered)
            if (namesNoNostrconnectPerms("$c,$c") != isWs) wrong += "U+%04X namesNothing".format(code)
        }
        assertTrue("trim disagrees with Rust's str::trim: ${wrong.take(20)}", wrong.isEmpty())
    }

    @Test
    fun randomCodePointPermsKeepTheApprovalInvariants() {
        val rnd = Random(645)
        val alphabet = listOf("sign_event", "nip44_encrypt", ",", ":", " ", "　", "😀", "\uD800", "\uDC00", "\u0000")
        repeat(20_000) {
            val perms = buildString {
                repeat(rnd.nextInt(0, 40)) {
                    if (rnd.nextBoolean()) append(alphabet[rnd.nextInt(alphabet.size)])
                    else appendCodePoint(rnd.nextInt(0, 0x110000).let { if (it in 0xD800..0xDFFF) 0x41 else it })
                }
            }
            val offered = offeredNostrconnectMethods(perms)
            assertTrue(perms, grantable.containsAll(offered))
            assertEquals(perms, offered.distinct(), offered)
            for (kept in listOf(emptySet(), offered.toSet())) {
                val approved = approvedNostrconnectPerms(offered, kept)
                assertTrue(approved.startsWith("get_public_key"))
                assertFalse(approved.split(',').any { it.isBlank() })
            }
        }
    }

    private fun StringBuilder.appendCodePoint(cp: Int): StringBuilder = append(String(Character.toChars(cp)))

    private fun String.hasLoneSurrogate(): Boolean =
        indices.any { i ->
            val c = this[i]
            (c.isHighSurrogate() && (i + 1 >= length || !this[i + 1].isLowSurrogate())) ||
                (c.isLowSurrogate() && (i == 0 || !this[i - 1].isHighSurrogate()))
        }

    // The core caps a name at 50 chars (code points), and so does the app's sanitizer, so a name
    // the core let through is never cut inside a surrogate pair.
    @Test
    fun aCoreCappedNameIsNotCutInsideASurrogatePair() {
        val name = "a" + "𝐀".repeat(49)
        assertEquals(50, name.codePointCount(0, name.length))
        val shown = nostrconnectDisplayName(name)
        assertNotNull(shown)
        assertFalse("lone surrogate in ${shown!!.map { "%04X".format(it.code) }}", shown.hasLoneSurrogate())
    }

    @Test
    fun aCoreCappedNameOfAstralLettersIsShownWhole() {
        val name = "𐐀".repeat(30)
        assertEquals(name, nostrconnectDisplayName(name))
    }

    @Test
    fun displayNameNeverThrowsAndNeverReturnsBlank() {
        val rnd = Random(6451)
        repeat(20_000) {
            val name = buildString {
                repeat(rnd.nextInt(0, 60)) { append(rnd.nextInt(0, 0x10000).toChar()) }
            }
            val shown = nostrconnectDisplayName(name)
            if (shown != null) assertTrue(shown.isNotBlank())
        }
    }

    @Test
    fun noNonAsciiCharCaseFoldsOntoAHexDigit() {
        val hex = "0123456789abcdefABCDEF"
        val folding = (0x80..0xFFFF).map { it.toChar() }.filter { c ->
            hex.any { h -> c.toString().equals(h.toString(), ignoreCase = true) }
        }
        assertTrue("chars that would match a listed hex key: $folding", folding.isEmpty())
    }

    @Test
    fun aListedEntryOnlyMatchesTheWholeKey() {
        val pk = "ab".repeat(32)
        for (entry in listOf(" $pk", "$pk ", pk.dropLast(1), pk + "0", "", "\u0000$pk")) {
            assertFalse(entry, admitsNostrconnectClient(listOf(entry), pk, 0, 0, null))
        }
        assertTrue(admitsNostrconnectClient(listOf(pk.uppercase()), pk, 0, 0, null))
    }

    @Test
    fun generationBoundaries() {
        val pk = "a".repeat(64)
        assertTrue(admitsNostrconnectClient(listOf(pk), pk, generation = 7, everyClientRevokedAt = 7, clientRevokedAt = 7))
        assertFalse(admitsNostrconnectClient(listOf(pk), pk, generation = 7, everyClientRevokedAt = 8, clientRevokedAt = 0))
        assertTrue(admitsNostrconnectClient(listOf(pk), pk, generation = Long.MAX_VALUE, everyClientRevokedAt = Long.MAX_VALUE, clientRevokedAt = null))
        assertFalse(admitsNostrconnectClient(listOf(pk), pk, generation = -1, everyClientRevokedAt = 0, clientRevokedAt = null))
        val many = List(100_000) { "%064x".format(it) } + pk
        assertTrue(admitsNostrconnectClient(many, pk, 0, 0, null))
    }
}
