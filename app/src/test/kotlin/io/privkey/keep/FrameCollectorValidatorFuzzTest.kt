package io.privkey.keep

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

// Plain text now reaches every scanner's validator. Each must reject what is not its own
// code without throwing, since the analyzer runs it on the camera executor.
class FrameCollectorValidatorFuzzTest {

    private val validators: Map<String, (String) -> Boolean> = mapOf(
        "kshare" to ::isValidKshareFormat,
        "setup" to ::isValidSetup,
        "subkey" to ::isValidSubkey,
        "roster" to ::isValidRoster,
        "nostrconnect" to { it.startsWith("nostrconnect://") },
        "approver" to { it.startsWith("keep-approver:v1?") },
    )

    private val seeds = listOf(
        "nostrconnect://${"a".repeat(64)}?relay=wss://r.example&secret=s",
        "keep-approver:v1?k=1", "nsec1qqqq", "bunker://x", "[" .repeat(3000), "\"", "null", "1e999999",
        "/*c*/{\"v\":2,\"k\":\"setup\"}", "#\n{\"f\":0,\"t\":1,\"d\":\"x\"}", "﻿{\"v\":2,\"k\":\"subkey\"}",
        "{\"v\":2,\"k\":\"subkey\",\"name\":\"g\",\"pk\":\"${"a".repeat(64)}\"}",
        "'; DROP TABLE x; --", "\$(id)", "%s%n%x", "../../../etc/passwd", "{{7*7}}",
    )

    private fun assertNoValidatorThrows(code: String) {
        val result = FrameCollector().processQrContent(code) ?: return
        for ((name, v) in validators) {
            try {
                v(result)
            } catch (t: Throwable) {
                throw AssertionError("$name threw ${t::class.simpleName} on ${result.take(80)}", t)
            }
        }
    }

    @Test
    fun seedsDoNotThrow() = seeds.forEach(::assertNoValidatorThrows)

    @Test
    fun randomPlainTextDoesNotThrowOrCrossScreens() {
        val rnd = Random(6452)
        val pieces = listOf("{", "}", "[", "]", "\"", ":", ",", "v", "k", "2", "nostrconnect://", "keep-approver:v1?", " ", "\\", "\u0000", "😀")
        repeat(30_000) {
            val code = buildString {
                repeat(rnd.nextInt(0, 30)) {
                    if (rnd.nextBoolean()) append(pieces[rnd.nextInt(pieces.size)]) else append(rnd.nextInt(0, 0xD800).toChar())
                }
            }
            if (code.trim().startsWith("kshare1")) return@repeat
            assertNoValidatorThrows(code)
        }
    }

    @Test
    fun aNostrconnectCodeIsTakenOnlyByTheBunkerScanner() {
        val uri = seeds[0]
        val result = FrameCollector().processQrContent(uri)!!
        val takers = validators.filterValues { it(result) }.keys
        assertEquals(setOf("nostrconnect"), takers)
    }

    @Test
    fun aCommentPrefixedFrameIsNoLongerCollected() {
        val c = FrameCollector()
        val framed = "#\n{\"f\":0,\"t\":2,\"d\":\"x\"}"
        assertEquals(framed, c.processQrContent(framed))
        assertFalse(c.isCollecting)
        assertFalse(isValidKshareFormat(framed))
    }

    @Test
    fun whitespaceTrimmedByKotlinButNotTheCoreDoesNotSurviveToTheValidator() {
        val uri = seeds[0]
        for (pad in listOf("\u001C", "\u001F", "\u3000", "\u00A0", "\u2028")) {
            assertEquals(uri, FrameCollector().processQrContent("$pad$uri$pad"))
        }
        val zw = FrameCollector().processQrContent("\u200B$uri")
        assertEquals("\u200B$uri", zw)
        assertFalse(zw!!.startsWith("nostrconnect://"))
    }

    @Test
    fun aQuoteOnlyOrBracketOnlyCodeIsHandedOnAsText() {
        assertEquals("[", FrameCollector().processQrContent("["))
        assertNull(FrameCollector().processQrContent("{"))
        assertTrue(validators.values.none { it("[") })
    }
}
