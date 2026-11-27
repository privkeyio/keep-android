package io.privkey.keep.nip46

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

// Checks the approval screen against the core's grant rules, ported from
// keep-nip46 handler.rs parse_permission_string and register_nostrconnect_client
// with the mobile bunker's connect grant (keep-mobile nip46.rs), so what the
// screen offers is what the core then grants.
class NostrConnectPermsStressTest {

    private val gpk = "get_public_key"
    private val mobileConnectGrant = setOf(gpk, "sign_event")
    private val coreMethods = setOf(
        gpk, "sign_event", "nip04_encrypt", "nip04_decrypt",
        "nip44_encrypt", "nip44_decrypt", "nip44v3_encrypt", "nip44v3_decrypt",
    )

    private fun rustTrim(s: String): String {
        fun ws(c: Char) = c in "\u0009\u000A\u000B\u000C\u000D\u0020\u0085\u00A0\u1680\u2028\u2029\u202F\u205F\u3000" ||
            c in '\u2000'..'\u200A'
        return s.dropWhile(::ws).dropLastWhile(::ws)
    }

    private fun coreParse(perms: String): Set<String> {
        val result = mutableSetOf<String>()
        for (part in perms.split(',')) {
            val t = rustTrim(part)
            if (t.startsWith("sign_event:")) result += "sign_event" else if (t in coreMethods) result += t
        }
        return if (result.isEmpty()) setOf(gpk) else result + gpk
    }

    private fun coreGrant(requested: String?, approved: String?): Set<String> {
        val req = requested
            ?.takeIf { p -> p.split(',').any { rustTrim(it).isNotEmpty() } }
            ?.let(::coreParse) ?: mobileConnectGrant
        return approved?.let { coreParse(it).intersect(req) } ?: req
    }

    private fun grantedWhenKeeping(perms: String?, kept: (List<String>) -> Set<String>): Set<String> {
        val offered = offeredNostrconnectMethods(perms)
        return coreGrant(perms, approvedNostrconnectPerms(offered, kept(offered)))
    }

    private fun violations(perms: String?): List<String> {
        val offered = offeredNostrconnectMethods(perms).toSet()
        val out = mutableListOf<String>()
        val all = grantedWhenKeeping(perms) { it.toSet() } - gpk
        if (all != offered) out += "kept all: offered=$offered granted=$all"
        val none = grantedWhenKeeping(perms) { emptySet() }
        if (none != setOf(gpk)) out += "kept none: granted=$none"
        return out
    }

    @Test
    fun aRequestNamingNoPermsOffersTheSignEventItGetsAndLetsItBeWithheld() {
        for (perms in listOf(null, "", " , ", ",,,")) {
            assertEquals(listOf("sign_event"), offeredNostrconnectMethods(perms))
            assertEquals(mobileConnectGrant, grantedWhenKeeping(perms) { it.toSet() })
            assertEquals(setOf(gpk), grantedWhenKeeping(perms) { emptySet() })
        }
    }

    @Test
    fun aRequestNamingOnlyUnknownMethodsIsOfferedNothingAndGetsOnlyThePublicKey() {
        for (perms in listOf("foo", "ping", "foo,bar", "SIGN_EVENT")) {
            assertEquals(emptyList<String>(), offeredNostrconnectMethods(perms))
            assertEquals(setOf(gpk), grantedWhenKeeping(perms) { it.toSet() })
        }
    }

    @Test
    fun aMethodWithAKindSuffixIsOfferedOnlyWhenTheCoreGrantsIt() {
        assertEquals(emptyList<String>(), offeredNostrconnectMethods("nip04_encrypt:4"))
        assertEquals(setOf(gpk), grantedWhenKeeping("nip04_encrypt:4") { it.toSet() })
        assertEquals(listOf("sign_event"), offeredNostrconnectMethods("sign_event:4"))
        assertEquals(setOf(gpk, "sign_event"), grantedWhenKeeping("sign_event:4") { it.toSet() })
    }

    @Test
    fun fuzzedPermsOfferExactlyWhatTheCoreGrants() {
        val tokens = listOf(
            "sign_event", "sign_event:1", "sign_event:", "nip04_encrypt", "nip44_decrypt:7",
            "nip04_encrypt:4", "nip44v3_encrypt", "get_public_key", "ping", "SIGN_EVENT", " ", "",
            " nip04_decrypt\u3000", "sign_event :1", "nip44_encrypt ", "\u001Fsign_event", "foo",
        )
        val rnd = Random(644)
        val bad = linkedMapOf<String, List<String>>()
        repeat(20_000) {
            val perms = List(rnd.nextInt(0, 6)) { tokens[rnd.nextInt(tokens.size)] }.joinToString(",")
            val v = violations(perms)
            if (v.isNotEmpty() && bad.size < 50) bad[perms] = v
        }
        assertTrue("offers that disagree with the core: $bad", bad.isEmpty())
    }

    @Test(timeout = 30_000)
    fun maxLengthAndPathologicalPermsStayFast() {
        offeredNostrconnectMethods(",".repeat(512))
        offeredNostrconnectMethods(":".repeat(512))
        offeredNostrconnectMethods("sign_event:1,".repeat(40))
        offeredNostrconnectMethods("x".repeat(1_000_000))
        assertEquals(listOf("sign_event"), offeredNostrconnectMethods("sign_event:1,".repeat(40)))
    }
}
