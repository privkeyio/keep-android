package io.privkey.keep

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Coverage for [handlePaste], the pure paste-parsing logic behind the mnemonic
 * recovery grid (gh keep-android ej4d). It decides how a pasted blob maps onto
 * the 12/24-word slots and when to switch the grid size; getting it wrong would
 * misplace or drop recovery words. The Compose grid itself is emulator-bound and
 * out of unit scope.
 */
class HandlePasteTest {

    private fun slots(): MutableList<String> = MutableList(24) { "" }

    // Letter-only words (handlePaste strips digits/punctuation), distinct so slot
    // placement is checkable. First 24 BIP39 words.
    private val w = listOf(
        "abandon", "ability", "able", "about", "above", "absent",
        "absorb", "abstract", "absurd", "abuse", "access", "accident",
        "account", "accuse", "achieve", "acid", "acoustic", "acquire",
        "across", "act", "action", "actor", "actress", "actual"
    )
    private val twelve = w.take(12).joinToString(" ")
    private val twentyFour = w.joinToString(" ")

    @Test
    fun fullTwelveWordPasteFillsFromStartAndKeepsCount() {
        val words = slots()
        var count = 12
        val ok = handlePaste(twelve, startIndex = 0, words = words, wordCount = 12,
            onWordCountChange = { count = it })
        assertTrue(ok)
        assertEquals(12, count)
        assertEquals("abandon", words[0])
        assertEquals("accident", words[11])
        assertEquals("", words[12])
    }

    @Test
    fun fullMnemonicResetsEffectiveStartToZero() {
        // Pasting a complete mnemonic into a later slot must ignore startIndex and
        // fill from 0, not offset the words.
        val words = slots()
        val ok = handlePaste(twelve, startIndex = 5, words = words, wordCount = 12,
            onWordCountChange = {})
        assertTrue(ok)
        assertEquals("abandon", words[0])
        assertEquals("accident", words[11])
    }

    @Test
    fun fullTwentyFourWordPastePromotesTwelveToTwentyFour() {
        val words = slots()
        var count = 12
        val ok = handlePaste(twentyFour, startIndex = 0, words = words, wordCount = 12,
            onWordCountChange = { count = it })
        assertTrue(ok)
        assertEquals(24, count)
        assertEquals("actual", words[23])
    }

    @Test
    fun moreThanTwentyFourWordsIsRejected() {
        val words = slots()
        var count = 12
        var rejected = false
        val ok = handlePaste((1..25).joinToString(" ") { "word$it" }, startIndex = 0,
            words = words, wordCount = 12, onWordCountChange = { count = it },
            onPasteRejected = { rejected = true })
        assertFalse(ok)
        assertTrue(rejected)
        assertEquals(12, count)
        assertEquals("", words[0])
    }

    @Test
    fun partialPasteOverflowingCurrentCountPromotesToTwentyFour() {
        // A non-full paste that runs past the current 12 slots grows the grid to 24
        // rather than dropping the overflow.
        val words = slots()
        var count = 12
        val ok = handlePaste("alpha beta gamma", startIndex = 11, words = words, wordCount = 12,
            onWordCountChange = { count = it })
        assertTrue(ok)
        assertEquals(24, count)
        assertEquals("alpha", words[11])
        assertEquals("beta", words[12])
        assertEquals("gamma", words[13])
    }

    @Test
    fun partialPasteRunningPastTwentyFourIsRejected() {
        val words = slots()
        var rejected = false
        val ok = handlePaste("alpha beta gamma", startIndex = 23, words = words, wordCount = 24,
            onWordCountChange = {}, onPasteRejected = { rejected = true })
        assertFalse(ok)
        assertTrue(rejected)
    }

    @Test
    fun punctuationAndCasingAreStripped() {
        val words = slots()
        handlePaste("Abandon, ABANDON!  a1bout", startIndex = 0, words = words, wordCount = 12,
            onWordCountChange = {})
        assertEquals("abandon", words[0])
        assertEquals("abandon", words[1])
        assertEquals("about", words[2])
    }
}
