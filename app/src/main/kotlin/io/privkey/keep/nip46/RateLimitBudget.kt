package io.privkey.keep.nip46

internal enum class RateLimitBudget { CONNECT, SIGNING }

// Isolates the unauthenticated `connect` budget from authorized signing so a
// connect flood (rotating pubkeys) cannot drain the signing budget.
internal fun rateLimitBudgetFor(isConnectRequest: Boolean): RateLimitBudget =
    if (isConnectRequest) RateLimitBudget.CONNECT else RateLimitBudget.SIGNING
