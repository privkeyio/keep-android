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

    // Mirrors BunkerService.handleApprovalRequest ordering: the gate runs first,
    // and only a RATE_LIMIT_THEN_PROCEED outcome consults limiterFor(isConnectRequest).
    private fun budgetConsulted(isAuthorized: Boolean, isConnectRequest: Boolean): RateLimitBudget? =
        when (requestGateDecision(isAuthorized, isConnectRequest)) {
            RequestGate.REJECT_UNAUTHORIZED -> null
            RequestGate.RATE_LIMIT_THEN_PROCEED -> rateLimitBudgetFor(isConnectRequest)
        }

    @Test
    fun unauthorizedNonConnectConsultsNoLimiter() {
        assertNull(budgetConsulted(isAuthorized = false, isConnectRequest = false))
    }

    @Test
    fun unauthorizedConnectDelegatesToConnectBudget() {
        assertEquals(
            RateLimitBudget.CONNECT,
            budgetConsulted(isAuthorized = false, isConnectRequest = true)
        )
    }

    @Test
    fun authorizedSigningDelegatesToSigningBudget() {
        assertEquals(
            RateLimitBudget.SIGNING,
            budgetConsulted(isAuthorized = true, isConnectRequest = false)
        )
    }

    @Test
    fun authorizedConnectDelegatesToConnectBudget() {
        assertEquals(
            RateLimitBudget.CONNECT,
            budgetConsulted(isAuthorized = true, isConnectRequest = true)
        )
    }
}
