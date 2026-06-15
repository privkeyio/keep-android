package io.privkey.keep.nip55

/**
 * Tamper-resistant tail marker for the NIP-55 audit chain, persisted OUTSIDE Room
 * (in the Keystore-backed encrypted prefs that also hold the HMAC key) so an
 * attacker with on-device Room write access cannot forge it.
 */
data class AuditAnchor(val latestEntryHash: String, val entryCount: Long)

/**
 * Reconciles the Rust chain walk against the stored [anchor] to catch attacks the
 * walk alone cannot see: tail truncation (newest rows deleted, leaving an
 * otherwise-valid prefix) and head fabrication (rows prepended, which the walk
 * would excuse as legacy / [ChainVerificationResult.PartiallyVerified]).
 *
 * A Rust integrity failure ([ChainVerificationResult.Broken]/[ChainVerificationResult.Tampered])
 * is never downgraded. A null anchor (first run on an upgraded install) defers to
 * the Rust result so the caller can trust-on-first-use seed it.
 *
 * A set [tamperDetected] sticky flag (out-of-band mutation caught at append/prune
 * time) is authoritative: it overrides any now-consistent chain the walk reports.
 *
 * Pure function: no storage, no native calls, fully unit-testable.
 */
internal fun resolveChainVerification(
    tamperDetected: Boolean,
    anchor: AuditAnchor?,
    entryCount: Long,
    latestEntryHash: String,
    latestEntryId: Long,
    rustResult: ChainVerificationResult
): ChainVerificationResult {
    if (tamperDetected) return ChainVerificationResult.Tampered(latestEntryId)
    if (rustResult is ChainVerificationResult.Broken || rustResult is ChainVerificationResult.Tampered) {
        return rustResult
    }
    if (anchor == null) return rustResult
    if (entryCount > anchor.entryCount) {
        return ChainVerificationResult.Tampered(latestEntryId)
    }
    if (entryCount < anchor.entryCount || latestEntryHash != anchor.latestEntryHash) {
        return ChainVerificationResult.Truncated(latestEntryId)
    }
    // Anchor matches the DB exactly (count + tail). A Rust Truncated here means the head
    // row's previousHash dangles, a sanctioned head prune whose post-commit anchor we
    // already advanced, not an attack: deleting head rows drops count below the anchor
    // (caught above) and altering the tail fails the tail-hash check above. The keystore
    // anchor (which a Room-write attacker cannot forge) vouches that this exact (count,
    // tail) is the pruned state, so trust it over the dangling-head walk.
    if (rustResult is ChainVerificationResult.Truncated) return ChainVerificationResult.Valid
    return rustResult
}

/**
 * Trust-on-first-use seed decision: only seed the anchor when there is none yet
 * (fresh/upgraded install) AND the Rust walk reports an intact chain, so a
 * corrupt chain is never baselined as the source of truth.
 */
internal fun shouldSeed(anchor: AuditAnchor?, rustResult: ChainVerificationResult): Boolean =
    anchor == null &&
        (rustResult is ChainVerificationResult.Valid ||
            rustResult is ChainVerificationResult.PartiallyVerified)

/**
 * True when the DB is exactly one append ahead of the [anchor] and that newest row
 * chains onto the anchored tail ([newestPreviousHash] == [AuditAnchor.latestEntryHash]).
 *
 * The anchor advances only after the Room transaction commits, so a crash (or a
 * not-yet-visible concurrent append) can leave a legitimately-appended row durable
 * while the anchor still trails by one. Re-pinning instead of flagging is safe: a
 * forged extra row cannot carry a valid HMAC [Nip55AuditLog.entryHash], so it is
 * still caught by the Rust walk at verify time. Callers that have a Rust result
 * should additionally require [rustIntact] before treating this as benign.
 *
 * A legitimate crash-resumed append always carries a real (non-empty) HMAC
 * [latestEntryHash]; an all-legacy head injection against the empty zero anchor has
 * an empty tail, so requiring [latestEntryHash] non-empty makes that injection fall
 * through to resolveChainVerification → Tampered instead of being anchored as history.
 */
internal fun isResumableAppend(
    anchor: AuditAnchor,
    entryCount: Long,
    newestPreviousHash: String?,
    latestEntryHash: String,
    rustIntact: Boolean
): Boolean =
    rustIntact &&
        latestEntryHash.isNotEmpty() &&
        entryCount == anchor.entryCount + 1L &&
        // The first row after a reset chains onto the empty zero anchor: its
        // previousHash is null, which must read as equal to the "" anchor tail.
        (newestPreviousHash ?: "") == anchor.latestEntryHash

/**
 * True when the DB has fewer rows than the [anchor] but its newest row's hash still
 * matches the anchored tail. That is exactly the footprint of a head prune (oldest
 * rows removed, tail untouched) whose post-commit anchor advance was lost to a crash:
 * safe to re-pin to the lower count. Tail truncation deletes the newest rows, so the
 * tail hash would differ and this stays false. Callers must require [rustIntact].
 */
internal fun isResumablePrune(
    anchor: AuditAnchor,
    entryCount: Long,
    latestEntryHash: String,
    rustIntact: Boolean
): Boolean =
    rustIntact &&
        entryCount < anchor.entryCount &&
        entryCount > 0L &&
        latestEntryHash == anchor.latestEntryHash
