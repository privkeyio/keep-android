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
 * Pure function: no storage, no native calls, fully unit-testable.
 */
internal fun resolveChainVerification(
    anchor: AuditAnchor?,
    entryCount: Long,
    latestEntryHash: String,
    latestEntryId: Long,
    rustResult: ChainVerificationResult
): ChainVerificationResult {
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
    return rustResult
}
