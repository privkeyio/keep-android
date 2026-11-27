package io.privkey.keep.nip46

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

class NostrConnectDisplayNameStressTest {

    private val pk = "ab".repeat(32)
    private fun cp(c: Int) = String(Character.toChars(c))
    private fun StringBuilder.appendCp(c: Int): StringBuilder = append(cp(c))

    private fun String.hasLoneSurrogate(): Boolean =
        indices.any { i ->
            val c = this[i]
            (c.isHighSurrogate() && (i + 1 >= length || !this[i + 1].isLowSurrogate())) ||
                (c.isLowSurrogate() && (i == 0 || !this[i - 1].isHighSurrogate()))
        }

    private fun String.cps() = codePointCount(0, length)

    // keep-nip46 bunker.rs strip_invisible + take(50): what the core hands the app.
    private fun coreName(raw: String): String = buildString {
        var n = 0
        raw.codePoints().forEach { c ->
            val control = Character.getType(c) == Character.CONTROL.toInt()
            val stripped = control || c in 0x200B..0x200F || c in 0x2028..0x202E || c in 0x2060..0x206F || c == 0x061C || c == 0xFEFF
            if (!stripped && n < 50) { appendCp(c); n++ }
        }
    }

    @Test
    fun sanitizeCapsAtExactlyFiftyCodePointsAtEveryBoundary() {
        for (unit in listOf("a", cp(0x1D400), cp(0x1F468) + "a")) {
            for (len in listOf(0, 1, 25, 49, 50, 51, 100, 10_000)) {
                val out = sanitizeDisplayName(unit.repeat(len))
                assertFalse(out.hasLoneSurrogate())
                assertTrue("$len", out.cps() <= 50)
            }
        }
        assertEquals(cp(0x1D400).repeat(50), sanitizeDisplayName(cp(0x1D400).repeat(51)))
        assertEquals(cp(0x1D400).repeat(50), sanitizeDisplayName(cp(0x1D400).repeat(50)))
        assertEquals("a".repeat(49) + cp(0x1D400), sanitizeDisplayName("a".repeat(49) + cp(0x1D400) + "b"))
    }

    @Test
    fun sanitizeCountsLoneSurrogatesAsOneCodePointEach() {
        val out = sanitizeDisplayName("a".repeat(49) + "\uD800\uDC00" + "b")
        assertEquals("a".repeat(49) + "\uD800\uDC00", out)
        val reversed = sanitizeDisplayName("a".repeat(49) + "\uDC00\uD800" + "b")
        assertEquals("a".repeat(49) + "\uDC00", reversed)
    }

    @Test
    fun randomAstralAndFormatNamesNeverSplitAPairOrShowAFormatChar() {
        val rnd = Random(6452)
        val pool = intArrayOf(
            0x41, 0x1D400, 0x1F600, 0xE0041, 0xE007F, 0x00AD, 0x180E, 0x200D, 0x2066, 0x0301,
            0x3164, 0x20, 0x3000, 0xFEFF, 0x061C, 0x10FFFD, 0xE0100, 0x13430, 0x1D173,
        )
        repeat(30_000) {
            val name = buildString {
                repeat(rnd.nextInt(0, 120)) {
                    val c = if (rnd.nextInt(4) == 0) rnd.nextInt(0, 0x110000).let { if (it in 0xD800..0xDFFF) 0x41 else it }
                    else pool[rnd.nextInt(pool.size)]
                    appendCp(c)
                }
            }
            val shown = nostrconnectDisplayName(name) ?: return@repeat
            assertFalse(shown.hasLoneSurrogate())
            assertTrue(shown.cps() <= 50)
            assertTrue(shown.codePoints().noneMatch { Character.getType(it) == Character.FORMAT.toInt() || it in 0xE0000..0xE007F })
            assertEquals(shown, shown.trim())
            assertTrue(shown.isNotBlank())
        }
    }

    @Test
    fun formatCharactersOutsideTheTestedSetAreDropped() {
        assertEquals("X", nostrconnectDisplayName("X" + cp(0xE0000) + cp(0xE007F)))
        assertEquals("X", nostrconnectDisplayName(cp(0x1D173) + "X" + cp(0x1D17A)))
        assertEquals("X", nostrconnectDisplayName(cp(0x13430) + "X" + cp(0xFFF9) + cp(0xFFFB)))
        assertEquals("X", nostrconnectDisplayName("\u0600X\u06DD\u070F\u08E2"))
        assertEquals("X", nostrconnectDisplayName(cp(0x110BD) + "X" + cp(0x1BCA0)))
        // A variation selector is a mark (Mn), so it is kept but never shown alone.
        assertEquals("X" + cp(0xE0100), nostrconnectDisplayName("X" + cp(0xE0100)))
    }

    @Test
    fun invisibleLetterAndMarkOnlyNamesFallBack() {
        val invisibles = listOf(
            "\u3164", "\u115F\u1160", "\uFFA0", "\u2800", "\u034F", "\u17B4\u17B5", "\u180B\u180C\u180D",
            "\uFE0F".repeat(50), cp(0xE0100).repeat(50), "\u0301".repeat(50), "\u3164 \u3164",
        )
        for (name in invisibles) {
            val label = name.map { "%04X".format(it.code) }.toString()
            assertNull(label, nostrconnectDisplayName(name))
            assertEquals(label, "App abababab", nostrconnectClientName(name, pk))
        }
    }

    @Test
    fun zalgoAndHugeNamesStayBoundedAndFast() {
        val t0 = System.nanoTime()
        val shown = nostrconnectDisplayName("D" + "\u0301\u0302\u0303".repeat(100_000) + "amus")!!
        assertTrue(shown.cps() <= 50)
        val tags = "Damus" + (0xE0000..0xE007F).joinToString("") { cp(it) }.repeat(2_000)
        assertEquals("Damus", nostrconnectDisplayName(tags))
        val ms = (System.nanoTime() - t0) / 1_000_000
        assertTrue("took $ms ms", ms < 5_000)
    }

    // Through the core no name reaches the app longer than 50 code points, so this only covers a
    // caller that skips the core's cap: it gets null, not sanitizeDisplayName's "Unknown App",
    // so the localized placeholder and the "App <key>" fallback still apply.
    @Test
    fun aNameCutShortOfItsFirstLetterFallsBack() {
        assertNull(nostrconnectDisplayName(" ".repeat(50) + "Damus"))
        assertEquals("App abababab", nostrconnectClientName("\u3000".repeat(50) + "Damus", pk))
    }

    @Test
    fun aCoreCappedNameOfLeadingWhitespaceFallsBack() {
        for (ws in listOf(" ", "\u3000", "\u00A0", "\u2003")) {
            val shown = nostrconnectDisplayName(coreName(ws.repeat(50) + "Damus"))
            assertNull("U+%04X".format(ws[0].code), shown)
        }
    }

    // Only for a name that did not come through the core, which strips Cc and U+2028/2029. They
    // would reach the biometric subtitle and the result toast, which are not single-line.
    @Test
    fun lineBreaksAreNotShown() {
        for (brk in listOf("\n", "\r", "\t", "\u0085", "\u2028", "\u2029")) {
            val shown = nostrconnectDisplayName("Damus${brk}Verified by Keep")!!
            assertFalse("U+%04X".format(brk[0].code), shown.contains(brk))
        }
    }

    @Test
    fun throughTheCoreNoLineBreakReachesTheScreen() {
        for (brk in listOf("\n", "\r", "\t", "\u0085", "\u2028", "\u2029", "\u000B", "\u000C")) {
            val shown = nostrconnectDisplayName(coreName("Damus${brk}Verified by Keep"))!!
            assertFalse(shown.contains(brk))
        }
    }

    @Test
    fun theListedNameAgreesWithTheShownOneForCoreCappedNames() {
        val rnd = Random(6453)
        val pool = intArrayOf(0x20, 0x3000, 0x0301, 0x00AD, 0xE0041, 0x3164, 0x2800, 0x41, 0x1D400, 0xFE0F, 0x0A)
        repeat(20_000) {
            val core = coreName(buildString { repeat(rnd.nextInt(0, 70)) { appendCp(pool[rnd.nextInt(pool.size)]) } })
            val listed = nostrconnectClientName(core, pk)
            val shown = nostrconnectDisplayName(core)
            assertEquals(shown ?: "App abababab", listed)
            assertFalse(listed == "Unknown App")
        }
    }
}
