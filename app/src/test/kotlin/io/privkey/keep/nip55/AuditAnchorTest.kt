package io.privkey.keep.nip55

import io.privkey.keep.storage.PrefRead
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Coverage for the audit-chain tail anchor (gh #308), which hardens the Rust
 * keyed-HMAC walk against tail truncation (newest rows deleted) and head
 * fabrication (legacy rows prepended) by an attacker with Room write access.
 * Anchor persistence is Keystore-backed and native-bound; only the pure
 * reconciliation/seed/tamper decisions are unit-tested here.
 */
class AuditAnchorTest {

    private val valid = ChainVerificationResult.Valid

    @Test
    fun cleanChainMatchingAnchorIsValid() {
        assertEquals(
            ChainVerificationResult.Valid,
            resolveChainVerification(false, AuditAnchor("hashB", 2L), 2L, "hashB", 2L, valid)
        )
    }

    @Test
    fun tailTruncationByCountIsTruncated() {
        // Newest row deleted: fewer rows than the anchor recorded.
        assertEquals(
            ChainVerificationResult.Truncated(1L),
            resolveChainVerification(false, AuditAnchor("hashB", 2L), 1L, "hashA", 1L, valid)
        )
    }

    @Test
    fun tailTruncationByHashIsTruncated() {
        // Same count but the most-recent hash no longer matches the anchor.
        assertEquals(
            ChainVerificationResult.Truncated(2L),
            resolveChainVerification(false, AuditAnchor("hashB", 2L), 2L, "hashX", 2L, valid)
        )
    }

    @Test
    fun headFabricationGrowingCountIsTampered() {
        // Prepended legacy rows: count grows; the Rust walk excuses them as legacy.
        assertEquals(
            ChainVerificationResult.Tampered(3L),
            resolveChainVerification(
                false, AuditAnchor("hashB", 2L), 3L, "hashB", 3L,
                ChainVerificationResult.PartiallyVerified(1)
            )
        )
    }

    @Test
    fun headFabricationWithRustValidIsStillTampered() {
        // Even when the walk reports a fully Valid chain, a count that outgrew the
        // anchor means rows were inserted out-of-band.
        assertEquals(
            ChainVerificationResult.Tampered(3L),
            resolveChainVerification(false, AuditAnchor("hashB", 2L), 3L, "hashB", 3L, valid)
        )
    }

    @Test
    fun firstRunWithoutAnchorDefersToRust() {
        assertEquals(valid, resolveChainVerification(false, null, 2L, "hashB", 2L, valid))
    }

    @Test
    fun emptyDbWithZeroAnchorIsValid() {
        assertEquals(
            ChainVerificationResult.Valid,
            resolveChainVerification(false, AuditAnchor("", 0L), 0L, "", 0L, valid)
        )
    }

    @Test
    fun rustTamperedIsNotDowngraded() {
        // An anchor match must not mask a tamper the Rust walk already found.
        assertEquals(
            ChainVerificationResult.Tampered(2L),
            resolveChainVerification(
                false, AuditAnchor("hashB", 2L), 2L, "hashB", 2L,
                ChainVerificationResult.Tampered(2L)
            )
        )
    }

    @Test
    fun rustBrokenIsNotDowngraded() {
        assertEquals(
            ChainVerificationResult.Broken(2L),
            resolveChainVerification(
                false, AuditAnchor("hashB", 2L), 1L, "hashA", 1L,
                ChainVerificationResult.Broken(2L)
            )
        )
    }

    @Test
    fun partiallyVerifiedWithMatchingAnchorIsPreserved() {
        val partial = ChainVerificationResult.PartiallyVerified(1)
        assertEquals(
            partial,
            resolveChainVerification(false, AuditAnchor("hashB", 3L), 3L, "hashB", 3L, partial)
        )
    }

    @Test
    fun sanctionedHeadPruneTruncatedIsDowngradedToValid() {
        // FIX 4: anchor matches the DB EXACTLY (count + tail), but the head prune dropped
        // the oldest rows so the new head's previousHash dangles and the Rust walk reports
        // Truncated. The keystore anchor vouches this exact (count, tail) is the pruned
        // state, so it must be trusted over the dangling-head walk: downgrade to Valid.
        assertEquals(
            ChainVerificationResult.Valid,
            resolveChainVerification(
                false, AuditAnchor("hashB", 3L), 3L, "hashB", 3L,
                ChainVerificationResult.Truncated(3L)
            )
        )
    }

    @Test
    fun truncatedNotDowngradedWhenCountBelowAnchor() {
        // FIX 4 safety: a real tail truncation drops the count below the anchor. Even with
        // a Rust Truncated this must stay Truncated, never be laundered into Valid.
        assertEquals(
            ChainVerificationResult.Truncated(2L),
            resolveChainVerification(
                false, AuditAnchor("hashB", 3L), 2L, "hashA", 2L,
                ChainVerificationResult.Truncated(2L)
            )
        )
    }

    @Test
    fun truncatedNotDowngradedWhenTailHashDiffers() {
        // FIX 4 safety: the count matches but the tail hash no longer matches the anchor
        // (tail row swapped). The tail-mismatch branch must catch it before the downgrade.
        assertEquals(
            ChainVerificationResult.Truncated(3L),
            resolveChainVerification(
                false, AuditAnchor("hashB", 3L), 3L, "hashX", 3L,
                ChainVerificationResult.Truncated(3L)
            )
        )
    }

    @Test
    fun stickyTamperFlagOverridesConsistentChain() {
        // Out-of-band mutation was caught at append/prune time and re-laundered into a
        // now-consistent chain; the sticky flag must still report tampering.
        assertEquals(
            ChainVerificationResult.Tampered(2L),
            resolveChainVerification(true, AuditAnchor("hashB", 2L), 2L, "hashB", 2L, valid)
        )
    }

    @Test
    fun stickyTamperFlagOverridesNullAnchor() {
        assertEquals(
            ChainVerificationResult.Tampered(2L),
            resolveChainVerification(true, null, 2L, "hashB", 2L, valid)
        )
    }

    @Test
    fun seedOnlyWhenAnchorNullAndRustValid() {
        assertTrue(shouldSeed(null, valid))
        assertTrue(shouldSeed(null, ChainVerificationResult.PartiallyVerified(2)))
    }

    @Test
    fun noSeedWhenRustChainIsBad() {
        assertFalse(shouldSeed(null, ChainVerificationResult.Broken(1L)))
        assertFalse(shouldSeed(null, ChainVerificationResult.Tampered(1L)))
        assertFalse(shouldSeed(null, ChainVerificationResult.Truncated(1L)))
    }

    @Test
    fun noSeedWhenAnchorPresent() {
        assertFalse(shouldSeed(AuditAnchor("hashB", 2L), valid))
        assertFalse(shouldSeed(AuditAnchor("", 0L), valid))
    }

    @Test
    fun resumableAppendWhenOneAheadChainedAndIntact() {
        // DB one row ahead, newest row chained onto the anchored tail, Rust intact:
        // a legit append whose post-commit anchor advance was lost to a crash.
        assertTrue(isResumableAppend(AuditAnchor("hashB", 2L), 3L, "hashB", "hashC", rustIntact = true))
    }

    @Test
    fun notResumableWhenNotChainedOntoAnchor() {
        // Newest row does not link to the anchored tail (e.g. head fabrication shifts it).
        assertFalse(isResumableAppend(AuditAnchor("hashB", 2L), 3L, "hashX", "hashC", rustIntact = true))
    }

    @Test
    fun notResumableWhenRustNotIntact() {
        // A forged extra row that the Rust walk rejects must never be healed.
        assertFalse(isResumableAppend(AuditAnchor("hashB", 2L), 3L, "hashB", "hashC", rustIntact = false))
    }

    @Test
    fun notResumableWhenNotExactlyOneAhead() {
        assertFalse(isResumableAppend(AuditAnchor("hashB", 2L), 2L, "hashB", "hashC", rustIntact = true))
        assertFalse(isResumableAppend(AuditAnchor("hashB", 2L), 4L, "hashB", "hashC", rustIntact = true))
        assertFalse(isResumableAppend(AuditAnchor("hashB", 2L), 1L, "hashB", "hashC", rustIntact = true))
    }

    @Test
    fun resumableFirstAppendAfterResetWithNullPreviousHash() {
        // After a clear/reset the zero anchor holds "" as the tail; the first real row
        // chains onto it with a null previousHash and a real (non-empty) HMAC hash,
        // which must read as resumable.
        assertTrue(isResumableAppend(AuditAnchor("", 0L), 1L, null, "hashA", rustIntact = true))
    }

    @Test
    fun notResumableWhenEmptyTailLegacyInjectionAgainstZeroAnchor() {
        // FIX 1: a single attacker-injected legacy row against the empty zero anchor has
        // an empty entryHash. It otherwise looks like a first post-reset append (count 1,
        // null previousHash, Rust excuses it as legacy), so the empty-tail guard is the
        // only thing stopping the forged history from being anchored. Must be rejected.
        assertFalse(isResumableAppend(AuditAnchor("", 0L), 1L, null, "", rustIntact = true))
    }

    @Test
    fun resumableWhenNonEmptyTailFirstAppendStillHeals() {
        // The legit crash-resumed first append carries a real HMAC tail, so the FIX 1
        // guard does not disturb the healing path.
        assertTrue(isResumableAppend(AuditAnchor("", 0L), 1L, null, "realHmac", rustIntact = true))
    }

    @Test
    fun resumablePruneWhenFewerRowsSameTailAndIntact() {
        // Crash-interrupted head prune: oldest rows gone, tail unchanged, Rust intact.
        assertTrue(isResumablePrune(AuditAnchor("hashB", 5L), 3L, "hashB", rustIntact = true))
    }

    @Test
    fun notResumablePruneWhenTailChanged() {
        // Tail truncation deletes the newest rows, so the tail hash differs: never excused.
        assertFalse(isResumablePrune(AuditAnchor("hashB", 5L), 3L, "hashA", rustIntact = true))
    }

    @Test
    fun notResumablePruneWhenRustNotIntact() {
        assertFalse(isResumablePrune(AuditAnchor("hashB", 5L), 3L, "hashB", rustIntact = false))
    }

    @Test
    fun notResumablePruneWhenCountNotLower() {
        assertFalse(isResumablePrune(AuditAnchor("hashB", 5L), 5L, "hashB", rustIntact = true))
        assertFalse(isResumablePrune(AuditAnchor("hashB", 5L), 6L, "hashB", rustIntact = true))
    }

    @Test
    fun notResumablePruneToEmpty() {
        // Prune that empties the DB changes the tail to "": indistinguishable from a full
        // wipe by state alone, so it is not excused here (the clear marker handles clears).
        assertFalse(isResumablePrune(AuditAnchor("hashB", 5L), 0L, "", rustIntact = true))
    }

    @Test
    fun anchorIsPinnedWhenBothHalvesRead() {
        val state = resolveAuditAnchorState(
            PrefRead.Found(2L),
            PrefRead.Found("hashB"),
            PrefRead.Found(false),
            PrefRead.Found(false)
        )

        assertEquals(AuditAnchor("hashB", 2L), state.anchor)
        assertFalse(state.unreadable)
        assertFalse(state.tamperDetected)
    }

    @Test
    fun resetAnchorIsPinnedRatherThanTreatedAsAbsent() {
        // What resetAuditAnchor writes. The zero anchor is a pin: it says the table is
        // empty, which is what makes a row appearing under it detectable.
        val state = resolveAuditAnchorState(
            PrefRead.Found(0L),
            PrefRead.Found(""),
            PrefRead.Found(false),
            PrefRead.Found(false)
        )

        assertEquals(AuditAnchor("", 0L), state.anchor)
        assertFalse(state.tamperDetected)
    }

    @Test
    fun bothHalvesAbsentIsAFirstRunRatherThanTamper() {
        // The only absence any writer here produces, and the one the caller seeds from.
        val state = resolveAuditAnchorState(PrefRead.Absent, PrefRead.Absent, PrefRead.Absent, PrefRead.Absent)

        assertNull(state.anchor)
        assertFalse(state.unreadable)
        assertFalse(state.tamperDetected)
    }

    @Test
    fun unreadableCountIsTamperRatherThanAFirstRun() {
        // The whole point: reading it as unpinned has the caller re-pin the anchor to
        // whatever the table now holds, which is what an attacker who corrupted this
        // entry after truncating the table is asking for.
        val state = resolveAuditAnchorState(
            PrefRead.Unreadable,
            PrefRead.Found("hashB"),
            PrefRead.Found(false),
            PrefRead.Found(false)
        )

        assertNull(state.anchor)
        assertTrue(state.unreadable)
        assertTrue(state.tamperDetected)
    }

    @Test
    fun unreadableHashIsTamper() {
        val state = resolveAuditAnchorState(
            PrefRead.Found(2L),
            PrefRead.Unreadable,
            PrefRead.Found(false),
            PrefRead.Found(false)
        )

        assertNull(state.anchor)
        assertTrue(state.tamperDetected)
    }

    @Test
    fun halfAbsentPairIsTamper() {
        // Both halves are written in one commit, so one of them alone is a pair that no
        // writer here produced. Deleting an entry takes the same access as corrupting it.
        assertTrue(
            resolveAuditAnchorState(
                PrefRead.Absent,
                PrefRead.Found("hashB"),
                PrefRead.Found(false),
                PrefRead.Found(false)
            ).tamperDetected
        )
        assertTrue(
            resolveAuditAnchorState(
                PrefRead.Found(2L),
                PrefRead.Absent,
                PrefRead.Found(false),
                PrefRead.Found(false)
            ).tamperDetected
        )
    }

    @Test
    fun negativeCountIsTamper() {
        // No writer stores one: the anchor count comes from a COUNT(*) or from the reset.
        val state = resolveAuditAnchorState(
            PrefRead.Found(-1L),
            PrefRead.Found("hashB"),
            PrefRead.Found(false),
            PrefRead.Found(false)
        )

        assertNull(state.anchor)
        assertTrue(state.tamperDetected)
    }

    @Test
    fun storedTamperFlagIsReportedWithoutBeingRewritten() {
        // flagged, not unreadable: the evidence is already recorded readably, so the
        // append path has nothing to write down again.
        val state = resolveAuditAnchorState(
            PrefRead.Found(2L),
            PrefRead.Found("hashB"),
            PrefRead.Found(true),
            PrefRead.Found(false)
        )

        assertEquals(AuditAnchor("hashB", 2L), state.anchor)
        assertTrue(state.flagged)
        assertFalse(state.unreadable)
        assertTrue(state.tamperDetected)
    }

    @Test
    fun absentTamperFlagIsNotTamper() {
        assertFalse(
            resolveAuditAnchorState(PrefRead.Absent, PrefRead.Absent, PrefRead.Absent, PrefRead.Absent).tamperDetected
        )
    }

    @Test
    fun unreadableTamperFlagIsTamperAndKeepsTheAnchorItReadsWith() {
        // Sticky evidence that will not decrypt is still evidence. The anchor halves read
        // fine here, so they stay pinned and only the flag drives the verdict.
        val state = resolveAuditAnchorState(
            PrefRead.Found(2L),
            PrefRead.Found("hashB"),
            PrefRead.Unreadable,
            PrefRead.Found(false)
        )

        assertEquals(AuditAnchor("hashB", 2L), state.anchor)
        assertFalse(state.flagged)
        assertTrue(state.unreadable)
        assertTrue(state.tamperDetected)
    }

    @Test
    fun aPinnedAnchorBesideAnAbsentTamperFlagIsTheSteadyState() {
        // Not tamper, and deliberately: setAuditAnchor writes only the two halves, so
        // this is where every install that has never flagged a tamper and never cleared
        // its history sits. The half-pair rule the anchor gets cannot be applied here
        // without flagging all of them, which is why the deletion hole this leaves is
        // closed by storing the four values as one entry rather than from the read side.
        val state = resolveAuditAnchorState(
            PrefRead.Found(2L),
            PrefRead.Found("hashB"),
            PrefRead.Absent,
            PrefRead.Absent
        )

        assertEquals(AuditAnchor("hashB", 2L), state.anchor)
        assertFalse(state.tamperDetected)
    }

    @Test
    fun aStoredTamperFlagSurvivesAnAnchorThatIsGone() {
        // Both halves deleted reads as a fresh install, so the flag is the only thing
        // that still says otherwise. It has to outweigh the absence.
        val state = resolveAuditAnchorState(
            PrefRead.Absent,
            PrefRead.Absent,
            PrefRead.Found(true),
            PrefRead.Absent
        )

        assertNull(state.anchor)
        assertTrue(state.tamperDetected)
    }

    @Test
    fun aStoredClearMarkerIsPendingAndNotTamper() {
        val state = resolveAuditAnchorState(
            PrefRead.Found(0L),
            PrefRead.Found(""),
            PrefRead.Found(false),
            PrefRead.Found(true)
        )

        assertTrue(state.clearPending)
        assertFalse(state.tamperDetected)
    }

    @Test
    fun anAbsentOrFalseClearMarkerIsNotPending() {
        assertFalse(
            resolveAuditAnchorState(
                PrefRead.Found(2L),
                PrefRead.Found("hashB"),
                PrefRead.Found(false),
                PrefRead.Absent
            ).clearPending
        )
        assertFalse(
            resolveAuditAnchorState(
                PrefRead.Found(2L),
                PrefRead.Found("hashB"),
                PrefRead.Found(false),
                PrefRead.Found(false)
            ).clearPending
        )
    }

    @Test
    fun anUnreadableClearMarkerIsNotPendingButIsStillRecorded() {
        // The asymmetry. Acting on it would complete a clear nobody requested against an
        // emptied table, which is the one state where the anchor still holds the evidence
        // of the truncation that emptied it. Recording it costs nothing and is the only
        // place that fault is ever written down.
        val state = resolveAuditAnchorState(
            PrefRead.Found(2L),
            PrefRead.Found("hashB"),
            PrefRead.Found(false),
            PrefRead.Unreadable
        )

        assertFalse(state.clearPending)
        assertTrue(state.unreadable)
        assertTrue(state.tamperDetected)
        assertEquals("the anchor halves read fine, so they stay pinned", AuditAnchor("hashB", 2L), state.anchor)
    }

    @Test
    fun verdictIsFalseWhenTheRowsMatchTheAnchor() {
        assertFalse(anchorMismatchVerdict(pinned(AuditAnchor("hashB", 2L)), 2L, "hashB", "hashA"))
    }

    @Test
    fun verdictIsFalseWithNoAnchorToCompareAgainst() {
        assertFalse(anchorMismatchVerdict(pinned(null), 2L, "hashB", "hashA"))
    }

    @Test
    fun verdictIsTrueWhenTheRowsDisagree() {
        assertTrue(anchorMismatchVerdict(pinned(AuditAnchor("hashB", 2L)), 1L, "hashA", null))
    }

    @Test
    fun verdictHealsTheResumableCases() {
        assertFalse(anchorMismatchVerdict(pinned(AuditAnchor("hashB", 2L)), 3L, "hashC", "hashB"))
        assertFalse(anchorMismatchVerdict(pinned(AuditAnchor("hashB", 5L)), 3L, "hashB", "hashA"))
    }

    @Test
    fun anUnreadableReadBeatsTheResumableCases() {
        // The footprint of a crash-resumed append, which would heal on its own. A fault
        // in the same pass has to win: the healing re-pins to an anchor it has read, and
        // there is no read to heal toward.
        val faulted = AuditAnchorState(
            anchor = AuditAnchor("hashB", 2L),
            flagged = false,
            clearPending = false,
            unreadable = true
        )

        assertTrue(anchorMismatchVerdict(faulted, 3L, "hashC", "hashB"))
    }

    @Test
    fun anAbsentAnchorMintsTheAuditSecret() {
        // The one absence a writer here produces, and an install from before the anchor
        // shipped sits in it with rows in the table. Refusing would close the app on it.
        assertFalse(auditChainExists(PrefRead.Absent, PrefRead.Absent))
    }

    @Test
    fun aZeroAnchorMintsTheAuditSecret() {
        // What resetAuditAnchor leaves behind: a sanctioned clear emptied the table, so a
        // new secret restarts a chain that has nothing in it.
        assertFalse(auditChainExists(PrefRead.Found(0L), PrefRead.Found("")))
    }

    @Test
    fun rowsChainedUnderTheSecretRefuseTheMint() {
        assertTrue(auditChainExists(PrefRead.Found(2L), PrefRead.Found("hashB")))
    }

    @Test
    fun anUnreadableAnchorHalfRefusesTheMint() {
        // Reading it as an absence is what lets the secret be replaced and the chain
        // restarted, which is the same reason the anchor reads refuse it.
        assertTrue(auditChainExists(PrefRead.Unreadable, PrefRead.Found("hashB")))
        assertTrue(auditChainExists(PrefRead.Found(2L), PrefRead.Unreadable))
        assertTrue(auditChainExists(PrefRead.Unreadable, PrefRead.Unreadable))
    }

    @Test
    fun aHalfAbsentAnchorRefusesTheMint() {
        // Both halves are written in one commit, so deleting only the count is the way
        // past this check, not a state to mint on.
        assertTrue(auditChainExists(PrefRead.Absent, PrefRead.Found("hashB")))
        assertTrue(auditChainExists(PrefRead.Found(2L), PrefRead.Absent))
    }

    @Test
    fun aNegativeCountRefusesTheMint() {
        assertTrue(auditChainExists(PrefRead.Found(-1L), PrefRead.Found("hashB")))
    }

    private fun pinned(anchor: AuditAnchor?) =
        AuditAnchorState(anchor, flagged = false, clearPending = false, unreadable = false)
}
