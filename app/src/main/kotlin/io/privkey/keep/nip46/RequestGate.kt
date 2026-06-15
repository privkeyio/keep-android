package io.privkey.keep.nip46

internal enum class RequestGate { REJECT_UNAUTHORIZED, RATE_LIMIT_THEN_PROCEED }

/**
 * Orders the NIP-46 request gates (gh #316): the denylist/authorization gate runs
 * before the shared global rate limiter so denylisted/unauthorized traffic cannot
 * burn the global budget. `connect` is the legitimate unauthenticated path, so it
 * passes the authorization gate but is still subject to rate limiting.
 *
 * - [RequestGate.REJECT_UNAUTHORIZED] — reject without consulting the rate limiter.
 * - [RequestGate.RATE_LIMIT_THEN_PROCEED] — apply the global rate limit, then proceed.
 *
 * Pure function: no Service state, no native calls, fully unit-testable.
 */
internal fun requestGateDecision(
    isAuthorized: Boolean,
    isConnectRequest: Boolean
): RequestGate =
    if (!isAuthorized && !isConnectRequest) {
        RequestGate.REJECT_UNAUTHORIZED
    } else {
        RequestGate.RATE_LIMIT_THEN_PROCEED
    }
