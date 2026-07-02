package io.privkey.keep.nip55

import io.privkey.keep.uniffi.Nip55RequestType

/**
 * Owns the singleTop batch-consent state machine for [Nip55Activity]: the pending
 * accumulation, the snapshot last displayed to the user, and the commit lock. It is
 * the single production home of the three TOCTOU guards (accumulate / render /
 * commit) that fix the HIGH consent-bypass finding (gh #372, commit `9a9bf6c`): the
 * signed/rejected set must equal the set the user saw on screen, so a request that
 * races in (via onNewIntent) after render but before the tap can never be folded in.
 *
 * The Activity delegates to this class rather than re-checking the guards inline, so
 * [BatchToctouRegressionTest] drives the real wiring: dropping a guard here fails the
 * test. Pure Kotlin, no Android or native dependencies, fully unit-testable.
 */
internal class BatchConsentGate<T, C>(
    private val maxBatchSize: Int,
    private val typeOf: (T) -> Nip55RequestType,
) {
    private val items = mutableListOf<T>()

    /** Requests accumulated for the current batch, in arrival order. Read-only. */
    val pending: List<T> get() = items

    /** Caller the current batch is bound to; a different caller resets the batch. */
    var batchCaller: String? = null
        private set

    /** The exact set captured at the last [render]; what a decision must act on. */
    var displayed: List<T> = emptyList()
        private set

    /**
     * The caller identity captured alongside [displayed] at the last [render]. A
     * decision must bind to this, never the live caller state, so a late
     * different-caller intent that swaps the live caller between render and the tap
     * cannot redirect the grant/trust/sign to the attacker's package (gh #372).
     */
    var displayedCaller: C? = null
        private set

    /** Set once [commit] succeeds; every later action is then ignored. */
    var decisionLocked = false
        private set

    /** True while the activity may still accumulate/render (no committed decision). */
    val admitsAction: Boolean get() = consentActionAdmitted(decisionLocked)

    /**
     * Mirrors [Nip55Activity.handleIntent] accumulation. Returns the taken
     * [BatchAccumulation] decision, or `null` when a committed decision has already
     * locked the batch (the item is not accumulated). On [BatchAccumulation.RESET]
     * [onReset] runs before the pending list is cleared, so callers can cancel
     * notifications for the requests being discarded while they are still present.
     */
    fun accumulate(item: T, caller: String, onReset: () -> Unit = {}): BatchAccumulation? {
        if (!admitsAction) return null
        val decision = batchAccumulationDecision(
            pendingTypes = items.map(typeOf),
            pendingCaller = batchCaller,
            newType = typeOf(item),
            newCaller = caller,
            maxBatchSize = maxBatchSize,
        )
        when (decision) {
            BatchAccumulation.DROP_OVER_CAP -> return decision
            BatchAccumulation.RESET -> {
                onReset()
                items.clear()
            }
            BatchAccumulation.ACCUMULATE -> {}
        }
        items.add(item)
        batchCaller = caller
        return decision
    }

    /**
     * Mirrors [Nip55Activity.setupContent]: capture the pending list (and the [caller]
     * that owns it) as the displayed snapshot and return it. Returns `null` (leaving
     * [displayed]/[displayedCaller] untouched) once a decision is locked, so a late
     * async render cannot re-capture a grown batch or a swapped caller.
     */
    fun render(caller: C): List<T>? {
        if (!admitsAction) return null
        displayed = items.toList()
        displayedCaller = caller
        return displayed
    }

    /**
     * Mirrors [Nip55Activity.handleApprove]/[Nip55Activity.handleReject]: lock the
     * batch and return the set the decision acts on, always the [displayed] snapshot
     * and never the live pending list. Returns `null` if a decision was already
     * committed, so a decision can never run twice.
     */
    fun commit(): List<T>? {
        if (!admitsAction) return null
        decisionLocked = true
        return consentBoundSet(displayed, items)
    }
}
