package io.privkey.keep.nip46

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Regression coverage for the NIP-46 gate ordering (gh #316): the global rate
 * limiter must only be consulted after the denylist/authorization gate, so
 * denylisted/unauthorized traffic cannot consume the shared global budget. The
 * Service flow (approval Activity, native signing) is out of unit scope.
 */
class RequestGateTest {

    @Test
    fun unauthorizedNonConnectRejectsWithoutRateLimiting() {
        // Denylisted/unauthorized requests are rejected before the limiter, so a
        // key-rotating attacker cannot burn the global budget.
        assertEquals(
            RequestGate.REJECT_UNAUTHORIZED,
            requestGateDecision(isAuthorized = false, isConnectRequest = false)
        )
    }

    @Test
    fun connectIsRateLimitedEvenWhenUnauthorized() {
        // connect is the legitimate unauthenticated path; it passes the auth gate
        // but must still be rate limited to avoid a new unauthenticated DoS hole.
        assertEquals(
            RequestGate.RATE_LIMIT_THEN_PROCEED,
            requestGateDecision(isAuthorized = false, isConnectRequest = true)
        )
    }

    @Test
    fun authorizedRequestIsRateLimited() {
        assertEquals(
            RequestGate.RATE_LIMIT_THEN_PROCEED,
            requestGateDecision(isAuthorized = true, isConnectRequest = false)
        )
    }

    @Test
    fun authorizedConnectIsRateLimited() {
        assertEquals(
            RequestGate.RATE_LIMIT_THEN_PROCEED,
            requestGateDecision(isAuthorized = true, isConnectRequest = true)
        )
    }
}
