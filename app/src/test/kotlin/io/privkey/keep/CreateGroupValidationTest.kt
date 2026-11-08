package io.privkey.keep

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Coverage for the QR envelope validators behind CreateGroupScreen's DKG ceremony
 * ([isValidSetup]/[isValidSubkey]/[isValidRoster]). These gate untrusted scanned
 * payloads before they drive a signing-group creation, so a shape that slips
 * through could seed a malformed roster or crash the parser. Pure logic; the
 * Compose flow itself is emulator-bound and out of unit scope.
 */
class CreateGroupValidationTest {

    private val hex64 = "a".repeat(64)
    private val hex64b = "b".repeat(64)
    private val hex64c = "c".repeat(64)

    private fun setup(
        name: String = "Group",
        th: Int = 2,
        n: Int = 3,
        v: Int = 2,
        k: String = "setup",
        relays: String = """["wss://relay.example"]"""
    ) = """{"v":$v,"k":"$k","name":"$name","th":$th,"n":$n,"relays":$relays}"""

    private fun subkey(
        name: String = "Group",
        pk: String = hex64,
        v: Int = 2,
        k: String = "subkey"
    ) = """{"v":$v,"k":"$k","name":"$name","pk":"$pk"}"""

    private fun roster(
        name: String = "Group",
        th: Int = 2,
        n: Int = 3,
        entries: String = """[{"i":1,"pk":"$hex64"},{"i":2,"pk":"$hex64b"},{"i":3,"pk":"$hex64c"}]""",
        v: Int = 2,
        k: String = "roster",
        relays: String = """["wss://relay.example"]"""
    ) = """{"v":$v,"k":"$k","name":"$name","th":$th,"n":$n,"relays":$relays,"r":$entries}"""

    @Test
    fun validSetupAccepted() = assertTrue(isValidSetup(setup()))

    @Test
    fun setupRejectsWrongKind() = assertFalse(isValidSetup(setup(k = "roster")))

    @Test
    fun setupRejectsWrongVersion() = assertFalse(isValidSetup(setup(v = 1)))

    @Test
    fun setupRejectsEmptyName() = assertFalse(isValidSetup(setup(name = "")))

    @Test
    fun setupRejectsThresholdAboveParticipants() = assertFalse(isValidSetup(setup(th = 4, n = 3)))

    @Test
    fun setupRejectsThresholdBelowMin() = assertFalse(isValidSetup(setup(th = 1, n = 3)))

    @Test
    fun setupRejectsTooManyParticipants() = assertFalse(isValidSetup(setup(n = 9)))

    @Test
    fun setupRejectsGarbage() = assertFalse(isValidSetup("not json"))

    @Test
    fun setupRejectsOversizedPayload() =
        assertFalse(isValidSetup(setup(name = "x".repeat(9000))))

    @Test
    fun validSubkeyAccepted() = assertTrue(isValidSubkey(subkey()))

    @Test
    fun subkeyRejectsWrongKind() = assertFalse(isValidSubkey(subkey(k = "setup")))

    @Test
    fun subkeyRejectsShortPubkey() = assertFalse(isValidSubkey(subkey(pk = "abcd")))

    @Test
    fun subkeyRejectsNonHexPubkey() = assertFalse(isValidSubkey(subkey(pk = "g".repeat(64))))

    @Test
    fun subkeyRejectsUppercasePubkey() = assertFalse(isValidSubkey(subkey(pk = "A".repeat(64))))

    @Test
    fun subkeyRejectsEmptyName() = assertFalse(isValidSubkey(subkey(name = "")))

    @Test
    fun validRosterAccepted() = assertTrue(isValidRoster(roster()))

    @Test
    fun rosterRejectsWrongKind() = assertFalse(isValidRoster(roster(k = "subkey")))

    @Test
    fun rosterRejectsEntryCountMismatch() =
        assertFalse(isValidRoster(roster(n = 3, entries = """[{"i":1,"pk":"$hex64"},{"i":2,"pk":"$hex64b"}]""")))

    @Test
    fun rosterRejectsIndexOutOfRange() =
        assertFalse(isValidRoster(roster(entries = """[{"i":1,"pk":"$hex64"},{"i":2,"pk":"$hex64b"},{"i":9,"pk":"$hex64c"}]""")))

    @Test
    fun rosterRejectsBadPubkeyEntry() =
        assertFalse(isValidRoster(roster(entries = """[{"i":1,"pk":"$hex64"},{"i":2,"pk":"$hex64b"},{"i":3,"pk":"nope"}]""")))

    @Test
    fun rosterRejectsMissingEntries() =
        assertFalse(isValidRoster("""{"v":2,"k":"roster","name":"Group","th":2,"n":3,"relays":[]}"""))

    @Test
    fun rosterRejectsThresholdAboveParticipants() = assertFalse(isValidRoster(roster(th = 4)))

    // Duplicate indices/pubkeys and a missing coordinator slot are well-formed at
    // the wire level, so the shape pre-check deliberately accepts them here; the
    // authoritative rejection is frost_verify_roster (Rust), exercised by the
    // keep-mobile dkg unit tests. Do not re-add the semantic checks to Kotlin.
    @Test
    fun rosterShapeCheckDefersDuplicateIndexToRust() =
        assertTrue(isValidRoster(roster(entries = """[{"i":1,"pk":"$hex64"},{"i":1,"pk":"$hex64b"},{"i":3,"pk":"$hex64c"}]""")))

    @Test
    fun rosterShapeCheckDefersDuplicatePubkeyToRust() =
        assertTrue(isValidRoster(roster(entries = """[{"i":1,"pk":"$hex64"},{"i":2,"pk":"$hex64"},{"i":3,"pk":"$hex64c"}]""")))

    @Test
    fun rosterShapeCheckDefersMissingCoordinatorIndexToRust() =
        assertTrue(isValidRoster(roster(entries = """[{"i":2,"pk":"$hex64"},{"i":3,"pk":"$hex64b"},{"i":3,"pk":"$hex64c"}]""")))

    @Test
    fun setupAcceptsWebsocketRelays() =
        assertTrue(isValidSetup(setup(relays = """["wss://relay.example","wss://relay2.example"]""")))

    @Test
    fun setupRejectsNonWebsocketRelay() =
        assertFalse(isValidSetup(setup(relays = """["https://relay.example"]""")))

    @Test
    fun setupRejectsPlaintextWsRelay() =
        assertFalse(isValidSetup(setup(relays = """["wss://relay.example","ws://localhost:7000"]""")))

    @Test
    fun setupRejectsOverlongRelay() =
        assertFalse(isValidSetup(setup(relays = """["wss://${"a".repeat(260)}"]""")))

    @Test
    fun setupRejectsTooManyRelays() =
        assertFalse(isValidSetup(setup(relays = (1..11).joinToString(",", "[", "]") { "\"wss://r$it\"" })))

    @Test
    fun setupRejectsOverlongName() = assertFalse(isValidSetup(setup(name = "x".repeat(65))))

    @Test
    fun setupRejectsBidiOverrideName() = assertFalse(isValidSetup(setup(name = "a\u202Eb")))

    @Test
    fun rosterRejectsOverlongName() = assertFalse(isValidRoster(roster(name = "x".repeat(65))))

    @Test
    fun rosterRejectsBidiOverrideName() = assertFalse(isValidRoster(roster(name = "a\u202Eb")))

    @Test
    fun setupRejectsNamesWithHiddenCharacters() {
        listOf(
            "a\u200Bb", // zero-width space
            "a\u2060b", // word joiner
            "a\u200Fb", // right-to-left mark
            "a\u061Cb", // Arabic letter mark
            "a\u2067b", // right-to-left isolate
            "a\uFEFFb", // byte order mark
            "a\u00ADb", // soft hyphen
            "a\uDB40\uDC41b", // tag character U+E0041
            "a\u2028b", // line separator
            "a\uD800b", // unpaired surrogate
            "a\u00A0b", // no-break space
            "a\u3000b", // ideographic space
            "a\u3164b", // Hangul filler
            "a\u2800b", // braille blank
            "a\u034Fb", // combining grapheme joiner
            "a\uE000b", // private use
            " Vault", // leading space
            "Vault ", // trailing space
            " ", // only a space
        ).forEach { name -> assertFalse(name, isValidSetup(setup(name = name))) }
    }

    @Test
    fun rosterRejectsNameWithZeroWidthCharacter() = assertFalse(isValidRoster(roster(name = "a\u200Bb")))

    @Test
    fun setupAcceptsVisibleNames() {
        listOf(
            "Family vault",
            "Familie Müller",
            "家族の金庫",
            "Семья",
            "🔑 Vault", // emoji outside the BMP
            "❤\uFE0F Vault", // emoji with a variation selector
            "👨\u200D👩\u200D👧 Vault", // ZWJ emoji sequence
            "می\u200Cخواهم", // Persian with ZWNJ
            "a\u0378b", // unassigned here, possibly assigned on a newer device
        ).forEach { name -> assertTrue(name, isValidSetup(setup(name = name))) }
    }

    @Test
    fun setupRejectsRelaysThatDisplayMisleadingly() {
        listOf(
            "wss://evil.example/\nwss://relay.example", // one entry shown as two
            "wss://evil.example/\u2028wss://relay.example",
            "wss://relay.example/\u202Eelpmaxe",
            "wss://relay.example/\u200B",
            "wss://relay.example/ x",
            "wss://relay.example@evil.example", // userinfo hides the host
            "wss://relay.exämple",
        ).forEach { relay ->
            val json = org.json.JSONArray(listOf(relay)).toString()
            assertFalse(relay, isValidSetup(setup(relays = json)))
        }
    }

    @Test
    fun setupRejectsDuplicateRelays() =
        assertFalse(isValidSetup(setup(relays = """["wss://relay.example","wss://relay.example"]""")))

    @Test
    fun rosterRejectsRelayWithNewline() =
        assertFalse(isValidRoster(roster(relays = org.json.JSONArray(listOf("wss://a.example/\nwss://b.example")).toString())))

    @Test
    fun rosterRejectsNonWebsocketRelay() =
        assertFalse(isValidRoster(roster(relays = """["ftp://relay.example"]""")))

    @Test
    fun setupRejectsEmptyRelayList() = assertFalse(isValidSetup(setup(relays = "[]")))

    @Test
    fun rosterRejectsEmptyRelayList() = assertFalse(isValidRoster(roster(relays = "[]")))
}
