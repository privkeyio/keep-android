package io.privkey.keep.nip46

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NostrConnectPermsTest {

    @Test
    fun kindsOfOneMethodCollapseIntoOneChoice() {
        assertEquals(
            listOf("sign_event", "nip44_encrypt"),
            offeredNostrconnectMethods("sign_event:1,sign_event:7,nip44_encrypt")
        )
    }

    @Test
    fun unknownMethodsAndGetPublicKeyAreNotOffered() {
        assertEquals(
            listOf("nip04_decrypt"),
            offeredNostrconnectMethods("get_public_key, nip04_decrypt ,switch_relays,ping")
        )
    }

    // The core grants a request naming no permission its connect grant, which signs.
    @Test
    fun blankPermsOfferTheConnectGrantsSignEvent() {
        for (perms in listOf(null, "", "   ", " , ", ",,,")) {
            assertTrue(namesNoNostrconnectPerms(perms))
            assertEquals(listOf("sign_event"), offeredNostrconnectMethods(perms))
        }
    }

    // Named but unknown is not blank: the core parses it to its default, get_public_key alone.
    @Test
    fun permsNamingOnlyUnknownMethodsOfferNothing() {
        assertFalse(namesNoNostrconnectPerms("foo"))
        assertEquals(emptyList<String>(), offeredNostrconnectMethods("foo"))
        assertEquals("get_public_key", approvedNostrconnectPerms(offeredNostrconnectMethods("foo"), emptySet()))
    }

    @Test
    fun onlySignEventTakesAKindSuffix() {
        assertEquals(listOf("sign_event"), offeredNostrconnectMethods("sign_event:4"))
        assertEquals(emptyList<String>(), offeredNostrconnectMethods("nip04_encrypt:4,nip44_decrypt:7"))
    }

    @Test
    fun aKeptSubsetIsGrantedWithGetPublicKey() {
        assertEquals(
            "get_public_key,sign_event",
            approvedNostrconnectPerms(listOf("sign_event", "nip44_encrypt"), setOf("sign_event"))
        )
    }

    // An approval naming nothing would be read as the default grant, so it always names get_public_key.
    @Test
    fun keepingNothingStillGrantsOnlyGetPublicKey() {
        assertEquals("get_public_key", approvedNostrconnectPerms(listOf("sign_event", "nip44_encrypt"), emptySet()))
        assertEquals("get_public_key", approvedNostrconnectPerms(emptyList(), emptySet()))
    }

    @Test
    fun grantedOrderFollowsTheOfferedList() {
        assertEquals(
            "get_public_key,sign_event,nip04_decrypt",
            approvedNostrconnectPerms(
                listOf("sign_event", "nip44_encrypt", "nip04_decrypt"),
                linkedSetOf("nip04_decrypt", "sign_event")
            )
        )
    }

    @Test
    fun aNameWithNothingVisibleIsUnknown() {
        assertNull(nostrconnectDisplayName(null))
        assertNull(nostrconnectDisplayName("   "))
        assertNull(nostrconnectDisplayName("\u3164\u3164"))
        assertNull(nostrconnectDisplayName("\u115F\u1160"))
        assertNull(nostrconnectDisplayName("\u0301\u0302"))
        assertNull(nostrconnectDisplayName("\u202E\u200B"))
        assertEquals("Damus", nostrconnectDisplayName(" Da\u202Emus "))
        assertEquals("7", nostrconnectDisplayName("7"))
    }

    // A revoke read under the config lock before the cache admits the client.
    @Test
    fun aRevokeBeforeTheAcceptDoesNotBlockIt() {
        val pk = "a".repeat(64)
        assertTrue(admitsNostrconnectClient(listOf(pk.uppercase()), pk, generation = 5, everyClientRevokedAt = 5, clientRevokedAt = 4))
    }

    @Test
    fun aRevokeAfterTheAcceptWins() {
        val pk = "a".repeat(64)
        assertFalse(admitsNostrconnectClient(emptyList(), pk, generation = 5, everyClientRevokedAt = 0, clientRevokedAt = null))
        assertFalse(admitsNostrconnectClient(listOf(pk), pk, generation = 5, everyClientRevokedAt = 0, clientRevokedAt = 6))
        assertFalse(admitsNostrconnectClient(listOf(pk), pk, generation = 5, everyClientRevokedAt = 6, clientRevokedAt = null))
    }

    @Test
    fun aRevokeOfAnotherClientDoesNotCount() {
        val pk = "a".repeat(64)
        assertTrue(admitsNostrconnectClient(listOf("b".repeat(64), pk), pk, generation = 5, everyClientRevokedAt = 0, clientRevokedAt = null))
    }
}
