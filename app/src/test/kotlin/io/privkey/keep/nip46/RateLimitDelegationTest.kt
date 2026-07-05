package io.privkey.keep.nip46

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Wiring coverage for the non-batch NIP-46 signer path (gh #377): proves the
 * Android layer composes the authorization gate and the budget selector so a
 * request is either rejected before any limiter is consulted, or delegated to
 * the correct Rust limiter budget. The limiter policy itself is unit-tested in
 * the Rust core; this only asserts the delegation seam.
 */
class RateLimitDelegationTest {

    // Exercises the same rateLimitBudgetDecision seam BunkerService.handleApprovalRequest
    // uses, so a production reordering (limiter consulted before the auth gate) fails here.

    @Test
    fun unauthorizedNonConnectConsultsNoLimiter() {
        assertNull(rateLimitBudgetDecision(isAuthorized = false, isConnectRequest = false))
    }

    @Test
    fun unauthorizedConnectDelegatesToConnectBudget() {
        assertEquals(
            RateLimitBudget.CONNECT,
            rateLimitBudgetDecision(isAuthorized = false, isConnectRequest = true)
        )
    }

    @Test
    fun authorizedSigningDelegatesToSigningBudget() {
        assertEquals(
            RateLimitBudget.SIGNING,
            rateLimitBudgetDecision(isAuthorized = true, isConnectRequest = false)
        )
    }

    @Test
    fun authorizedConnectDelegatesToConnectBudget() {
        assertEquals(
            RateLimitBudget.CONNECT,
            rateLimitBudgetDecision(isAuthorized = true, isConnectRequest = true)
        )
    }
}
