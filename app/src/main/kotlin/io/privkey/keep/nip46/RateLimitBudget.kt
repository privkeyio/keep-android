package io.privkey.keep.nip46

internal enum class RateLimitBudget { CONNECT, SIGNING }

// Isolates the unauthenticated `connect` budget from authorized signing so a
// connect flood (rotating pubkeys) cannot drain the signing budget.
internal fun rateLimitBudgetFor(isConnectRequest: Boolean): RateLimitBudget =
    if (isConnectRequest) RateLimitBudget.CONNECT else RateLimitBudget.SIGNING

// Single delegation seam shared by BunkerService and RateLimitDelegationTest:
// runs the authorization gate before selecting a limiter budget so a reordering
// regression (limiter consulted before the gate) is caught in one place.
// null = gate rejected, no limiter must be consulted; non-null = apply that budget.
internal fun rateLimitBudgetDecision(
    isAuthorized: Boolean,
    isConnectRequest: Boolean
): RateLimitBudget? =
    when (requestGateDecision(isAuthorized, isConnectRequest)) {
        RequestGate.REJECT_UNAUTHORIZED -> null
        RequestGate.RATE_LIMIT_THEN_PROCEED -> rateLimitBudgetFor(isConnectRequest)
    }
