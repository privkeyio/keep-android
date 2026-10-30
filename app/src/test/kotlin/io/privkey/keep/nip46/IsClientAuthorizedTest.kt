package io.privkey.keep.nip46

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Coverage for the authorization boolean that gates NIP-46 non-connect requests
 * ([isClientAuthorized]). It feeds [requestGateDecision]; getting it wrong would
 * either serve an unauthorized client or deny an authorized one. The cache
 * population / eviction / revoke paths are Service state and out of unit scope.
 */
class IsClientAuthorizedTest {

    @Test
    fun authorizedViaCache() {
        assertTrue(isClientAuthorized(inPendingAuth = false, inCache = true))
    }

    @Test
    fun authorizedViaPendingAuthWarmStart() {
        // A client that just completed connect approval, before its persisted
        // authorization was reloaded into the cache, is authorized via pendingAuth.
        assertTrue(isClientAuthorized(inPendingAuth = true, inCache = false))
    }

    @Test
    fun unknownClientIsUnauthorized() {
        // Present in neither set -> not authorized (re-prompt).
        assertFalse(isClientAuthorized(inPendingAuth = false, inCache = false))
    }
}
