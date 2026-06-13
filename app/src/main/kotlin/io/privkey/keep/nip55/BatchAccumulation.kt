package io.privkey.keep.nip55

import io.privkey.keep.uniffi.Nip55RequestType

internal enum class BatchAccumulation { ACCUMULATE, DROP_OVER_CAP, RESET }

/**
 * Decides what happens to a newly-parsed NIP-55 request relative to the requests
 * already pending in a singleTop [Nip55Activity]:
 *
 * - [BatchAccumulation.ACCUMULATE] — append it to the pending batch.
 * - [BatchAccumulation.DROP_OVER_CAP] — ignore it; the batch is already at the cap.
 * - [BatchAccumulation.RESET] — clear the pending batch and start fresh with it.
 *
 * Only same-caller *operation* requests accumulate. `get_public_key` never batches
 * (neither a new one nor one already pending), and a request from a different
 * caller resets — both guard against folding unrelated requests into one approval.
 *
 * Pure function: no Activity state, no native calls, fully unit-testable.
 */
internal fun batchAccumulationDecision(
    pendingTypes: List<Nip55RequestType>,
    pendingCaller: String?,
    newType: Nip55RequestType,
    newCaller: String,
    maxBatchSize: Int
): BatchAccumulation {
    val batchable = newType != Nip55RequestType.GET_PUBLIC_KEY
    val canAccumulate = pendingTypes.isNotEmpty() &&
        batchable &&
        pendingCaller == newCaller &&
        pendingTypes.all { it != Nip55RequestType.GET_PUBLIC_KEY }
    return when {
        !canAccumulate -> BatchAccumulation.RESET
        pendingTypes.size >= maxBatchSize -> BatchAccumulation.DROP_OVER_CAP
        else -> BatchAccumulation.ACCUMULATE
    }
}
