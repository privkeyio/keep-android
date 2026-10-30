package io.privkey.keep.nip46

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RevokedClientSetTest {

    @Test
    fun aSingleRevokeCoversOnlyTheNamedClient() {
        assertEquals(setOf(A), revokedClientSet(listOf(A), configured = listOf(A, B), cached = listOf(C), pending = listOf(D)))
    }

    // A client can be authorized in the cache or mid-save without being in the config yet,
    // and Revoke All has to reach it there too.
    @Test
    fun revokeAllCoversTheConfigTheCacheAndConnectsStillBeingSaved() {
        assertEquals(setOf(A, B, C, D), revokedClientSet(null, configured = listOf(A, B), cached = listOf(C), pending = listOf(D)))
    }

    @Test
    fun pubkeysAreLowercasedAndDeduplicated() {
        assertEquals(setOf(A), revokedClientSet(null, configured = listOf(A.uppercase()), cached = listOf(A), pending = emptyList()))
    }

    @Test
    fun revokeAllWithNoClientsCoversNothing() {
        assertEquals(emptySet<String>(), revokedClientSet(null, emptyList(), emptyList(), emptyList()))
    }

    @Test
    fun aRevokeOfAnotherClientDoesNotDropAConnectBeingSaved() {
        assertFalse(revokedSince(generation = 3, everyClientRevokedAt = 0, clientRevokedAt = null))
        assertFalse(revokedSince(generation = 3, everyClientRevokedAt = 2, clientRevokedAt = 1))
    }

    @Test
    fun aRevokeOfThisClientOrOfEveryClientAfterTheStartDropsTheSave() {
        assertTrue(revokedSince(generation = 3, everyClientRevokedAt = 0, clientRevokedAt = 4))
        assertTrue(revokedSince(generation = 3, everyClientRevokedAt = 4, clientRevokedAt = null))
    }

    private companion object {
        val A = "a".repeat(64)
        val B = "b".repeat(64)
        val C = "c".repeat(64)
        val D = "d".repeat(64)
    }
}
