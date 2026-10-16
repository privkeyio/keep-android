package io.privkey.keep.nip55

import io.privkey.keep.storage.PrefRead

/**
 * Tamper-resistant tail marker for the NIP-55 audit chain, persisted OUTSIDE Room
 * (in the Keystore-backed encrypted prefs that also hold the HMAC key) so an
 * attacker with on-device Room write access cannot forge it.
 */
data class AuditAnchor(val latestEntryHash: String, val entryCount: Long)

/**
 * The four stored values that carry the anchor, as one read of them leaves it.
 *
 * [unreadable] is the case the ordinary getters cannot report. A value that is on disk
 * and will not decrypt reads as the caller's default, which here means "nothing is
 * pinned" for the anchor and "nothing seen" for the two markers, and those are the
 * answer an attacker with write access to the preferences file wants: an unpinned anchor
 * is re-pinned to whatever the audit table now holds, and a cleared flag drops the
 * evidence that the table was ever mutated out of band. Corrupting one entry takes the
 * same access as deleting it, so neither may be read as an absence.
 *
 * [flagged] is the stored flag alone, so the append path can tell evidence it has
 * already recorded from evidence it still has to write down.
 *
 * The rule is not applied to an absent tamper flag, because [setAuditAnchor] writes only
 * the two anchor halves and [resetAuditAnchor] is the only writer that touches all four,
 * so a pinned anchor beside an absent flag is the steady state of every install that has
 * never flagged a tamper and never cleared its history. Deleting the flag entry after it
 * was set therefore reads as that state, which is a hole this cannot close from the read
 * side; closing it means holding the four values in one entry so an absence is not
 * representable. Tracked separately.
 */
internal data class AuditAnchorState(
    val anchor: AuditAnchor?,
    val flagged: Boolean,
    val clearPending: Boolean,
    val unreadable: Boolean
) {
    val tamperDetected: Boolean get() = flagged || unreadable
}

/**
 * Decides the anchor from the four reads, treating one that produced no value as tamper
 * rather than as a fresh install.
 *
 * Both halves of the anchor are written in a single commit and no writer stores a
 * negative count, so a pair that is neither both absent nor both present is a pair no
 * writer here produced. Only both-absent is a genuine absence: the first launch on an
 * install that predates the anchor, which the caller trust-on-first-use seeds.
 *
 * [clearMarker] is the one value whose fault does not change what the caller does with
 * it: only a stored true is a pending clear. Acting on a marker that will not decrypt
 * sends the reconcile into resetAuditAnchor against a table nobody emptied, which
 * completes a clear nobody asked for and destroys the anchor evidence of the truncation
 * that left the table empty, and an emptied table against a pinned anchor is caught by
 * the next write anyway, since neither resumable case covers an empty tail against a
 * non-empty anchor hash. It is still evidence, so it counts toward [unreadable]: not
 * acting on a fault and not recording it are separate decisions, and nothing else in the
 * file ever rewrites that entry.
 *
 * Pure function: no storage, no native calls, fully unit-testable.
 */
internal fun resolveAuditAnchorState(
    count: PrefRead<Long>,
    hash: PrefRead<String>,
    tamperFlag: PrefRead<Boolean>,
    clearMarker: PrefRead<Boolean>
): AuditAnchorState {
    val flagged = tamperFlag is PrefRead.Found && tamperFlag.value
    val clearPending = clearMarker is PrefRead.Found && clearMarker.value
    val markerFault = tamperFlag is PrefRead.Unreadable || clearMarker is PrefRead.Unreadable
    if (count is PrefRead.Absent && hash is PrefRead.Absent) {
        return AuditAnchorState(null, flagged, clearPending, markerFault)
    }
    if (count is PrefRead.Found && hash is PrefRead.Found && count.value >= 0L) {
        return AuditAnchorState(AuditAnchor(hash.value, count.value), flagged, clearPending, markerFault)
    }
    return AuditAnchorState(null, flagged, clearPending, unreadable = true)
}

/**
 * Whether rows are chained under the audit HMAC secret, which is what refuses to mint a
 * replacement over an absent one.
 *
 * Minting restarts the chain: every row written under the old secret stops verifying, and
 * nothing records that the secret changed. The Rust walk does report the first old-secret
 * row as tampered, but only when something asks it to, and the 30-day prune that runs on
 * every launch deletes those rows, after which the walk reports a dangling head that
 * [resolveChainVerification] trusts the anchor over and calls valid.
 *
 * The anchor count is the signal rather than the database file, which is non-empty from
 * first use onward whether or not an audit row was ever chained, so refusing on it would
 * refuse a lost secret with nothing to lose. The anchor advance follows every append and
 * prune and [resetAuditAnchor] zeroes the count after a sanctioned clear, so a count
 * above zero means rows are chained under the secret being replaced.
 *
 * Both halves absent has to mint: an install from before the anchor shipped (v1.1.5) has
 * none, and can upgrade at any later date with rows still inside the prune window, so
 * refusing would close the app on it. Deleting both halves is therefore a way past this,
 * and not closable from the read side for the same reason.
 *
 * Every other shape refuses, on the pair rule [resolveAuditAnchorState] uses: a
 * half-present pair or an unreadable half is a pair no writer here produced, and a
 * negative count is one no writer stores.
 *
 * Pure function: no storage, no native calls, fully unit-testable.
 */
internal fun auditChainExists(count: PrefRead<Long>, hash: PrefRead<String>): Boolean {
    if (count is PrefRead.Absent && hash is PrefRead.Absent) return false
    return !(count is PrefRead.Found && hash is PrefRead.Found && count.value == 0L)
}

/**
 * Whether the rows an audit write is about to change disagree with the anchor they were
 * pinned against, which is out-of-band mutation.
 *
 * An unreadable read takes precedence over every healing case below: those re-pin to an
 * anchor they have read, and a fault means there is no anchor to heal toward.
 *
 * Pure function over the row facts the caller supplies: no storage, no DAO.
 */
internal fun anchorMismatchVerdict(
    state: AuditAnchorState,
    entryCount: Long,
    latestEntryHash: String,
    newestPreviousHash: String?
): Boolean {
    if (state.unreadable) return true
    val anchor = state.anchor ?: return false
    if (latestEntryHash == anchor.latestEntryHash && entryCount == anchor.entryCount) return false
    // A legit append whose post-commit anchor advance was lost to a crash leaves the DB
    // one row ahead, chained onto the anchored tail. Re-pin without flagging.
    if (isResumableAppend(anchor, entryCount, newestPreviousHash, latestEntryHash, rustIntact = true)) {
        return false
    }
    // Likewise a crash-interrupted head prune: fewer rows but the same tail. The Rust
    // walk at verify time is authoritative for the rustIntact assumption here.
    if (isResumablePrune(anchor, entryCount, latestEntryHash, rustIntact = true)) return false
    return true
}

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
 *
 * [ChainVerificationResult.PartiallyVerified] (leading legacy/empty-hash rows) is
 * intentionally seeded, NOT declined. Seeding pins the total count so any LATER
 * prepend or truncation is caught by [resolveChainVerification]; declining would
 * leave the anchor null and forfeit that forward protection. The only residual —
 * legacy rows prepended BEFORE this first seed — is already excused-as-legacy by
 * the Rust walk whether or not we seed, and is bounded to 1024 rows by the Rust
 * leading-legacy cap (keep PR #842). PartiallyVerified is also effectively
 * unreachable in the field: legacy rows are pruned at 30 days on every launch.
 * If a strict chained-count guarantee is ever required, wire the Rust tip MAC
 * (`nip55VerifyAuditChainWithTip`, already chained-count based) rather than
 * reworking this total-count anchor. See keep-android-6mjx.
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
