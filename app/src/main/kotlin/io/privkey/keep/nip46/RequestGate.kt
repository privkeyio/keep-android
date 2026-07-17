package io.privkey.keep.nip46

import io.privkey.keep.uniffi.ConnectAuthorization

internal enum class RequestGate { REJECT_UNAUTHORIZED, RATE_LIMIT_THEN_PROCEED }

/**
 * Whether a completed NIP-46 connect should be persisted as an authorized client.
 * Authorization is driven by the signer core's explicit assertion of why the
 * connect was accepted: only an explicit-consent reason (a matched connect secret
 * or a user-approved prompt) persists. `AUTO_APPROVED` means the core accepted the
 * connect with neither a secret nor a prompt, so it must NOT be persisted as
 * authorized. This removes the reliance on the callback merely having fired.
 *
 * Pure function: no Service state, no native calls, fully unit-testable.
 */
internal fun shouldPersistConnectAuthorization(authorization: ConnectAuthorization): Boolean =
    when (authorization) {
        ConnectAuthorization.SECRET_MATCHED, ConnectAuthorization.USER_APPROVED -> true
        ConnectAuthorization.AUTO_APPROVED -> false
    }

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

/**
 * Whether a NIP-46 client is authorized to have its (non-connect) requests
 * served. The denylist always wins; otherwise the client must be present in
 * either the warm-start `pending-auth` set (it just completed a connect
 * approval before its persisted authorization was reloaded into the cache) or
 * the authorized-clients cache. This is the security-critical authorization
 * boolean feeding [requestGateDecision].
 *
 * Pure function: no Service state, no native calls, fully unit-testable.
 */
internal fun isClientAuthorized(
    denylisted: Boolean,
    inPendingAuth: Boolean,
    inCache: Boolean
): Boolean = !denylisted && (inPendingAuth || inCache)
