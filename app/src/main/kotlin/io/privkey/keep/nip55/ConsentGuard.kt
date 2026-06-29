package io.privkey.keep.nip55

/**
 * Decides whether an incoming action against a singleTop [Nip55Activity] is
 * admitted, given whether the user has already committed an approve/reject
 * decision ([decisionLocked]).
 *
 * Once a decision is committed the activity is finishing on exactly the set the
 * user saw, so every later action — a second approve/reject tap, a late-arriving
 * intent ([Nip55Activity.handleIntent]), or a late async risk render
 * ([Nip55Activity.calculateRiskAndSetupContent] / [Nip55Activity.setupContent]) —
 * must be ignored. The invariant: a committed decision can never run twice or be
 * resurrected.
 *
 * Returns `true` to proceed, `false` to ignore.
 *
 * Pure function: no Activity state, no native calls, fully unit-testable.
 */
internal fun consentActionAdmitted(decisionLocked: Boolean): Boolean = !decisionLocked

/**
 * Returns the snapshot an approve/reject decision must act on: always the
 * [displayed] set captured at render time, never the live [pending] list.
 *
 * A request that races in (via onNewIntent) after the UI was rendered but before
 * the user taps lands in [pending], not in [displayed]. Binding the decision to
 * [displayed] guarantees that late request can never be folded into the signed
 * (or rejected) set. The [pending] parameter is accepted only to make the binding
 * explicit and testable; it is intentionally not consulted.
 *
 * Pure function: no Activity state, no native calls, fully unit-testable.
 */
internal fun <T> consentBoundSet(displayed: List<T>, pending: List<T>): List<T> = displayed
