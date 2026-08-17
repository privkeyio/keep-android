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

    @Test
    fun rosterRejectsDuplicateIndex() =
        assertFalse(isValidRoster(roster(entries = """[{"i":1,"pk":"$hex64"},{"i":1,"pk":"$hex64b"},{"i":3,"pk":"$hex64c"}]""")))

    @Test
    fun rosterRejectsDuplicatePubkey() =
        assertFalse(isValidRoster(roster(entries = """[{"i":1,"pk":"$hex64"},{"i":2,"pk":"$hex64"},{"i":3,"pk":"$hex64c"}]""")))

    @Test
    fun rosterRejectsMissingCoordinatorIndex() =
        assertFalse(isValidRoster(roster(entries = """[{"i":2,"pk":"$hex64"},{"i":3,"pk":"$hex64b"},{"i":3,"pk":"$hex64c"}]""")))

    @Test
    fun setupAcceptsWebsocketRelays() =
        assertTrue(isValidSetup(setup(relays = """["wss://relay.example","ws://localhost:7000"]""")))

    @Test
    fun setupRejectsNonWebsocketRelay() =
        assertFalse(isValidSetup(setup(relays = """["https://relay.example"]""")))

    @Test
    fun setupRejectsTooManyRelays() =
        assertFalse(isValidSetup(setup(relays = (1..17).joinToString(",", "[", "]") { "\"wss://r$it\"" })))

    @Test
    fun rosterRejectsNonWebsocketRelay() =
        assertFalse(isValidRoster(roster(relays = """["ftp://relay.example"]""")))

    @Test
    fun setupRejectsEmptyRelayList() = assertFalse(isValidSetup(setup(relays = "[]")))

    @Test
    fun rosterRejectsEmptyRelayList() = assertFalse(isValidRoster(roster(relays = "[]")))
}
