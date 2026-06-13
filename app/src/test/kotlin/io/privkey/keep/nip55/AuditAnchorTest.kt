package io.privkey.keep.nip55

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
    fun rustTruncatedPassesThroughWhenAnchorMatches() {
        // Anchor is consistent but the keyed walk itself found a break: surface it.
        assertEquals(
            ChainVerificationResult.Truncated(2L),
            resolveChainVerification(
                false, AuditAnchor("hashB", 2L), 2L, "hashB", 2L,
                ChainVerificationResult.Truncated(2L)
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
        assertTrue(isResumableAppend(AuditAnchor("hashB", 2L), 3L, "hashB", rustIntact = true))
    }

    @Test
    fun notResumableWhenNotChainedOntoAnchor() {
        // Newest row does not link to the anchored tail (e.g. head fabrication shifts it).
        assertFalse(isResumableAppend(AuditAnchor("hashB", 2L), 3L, "hashX", rustIntact = true))
    }

    @Test
    fun notResumableWhenRustNotIntact() {
        // A forged extra row that the Rust walk rejects must never be healed.
        assertFalse(isResumableAppend(AuditAnchor("hashB", 2L), 3L, "hashB", rustIntact = false))
    }

    @Test
    fun notResumableWhenNotExactlyOneAhead() {
        assertFalse(isResumableAppend(AuditAnchor("hashB", 2L), 2L, "hashB", rustIntact = true))
        assertFalse(isResumableAppend(AuditAnchor("hashB", 2L), 4L, "hashB", rustIntact = true))
        assertFalse(isResumableAppend(AuditAnchor("hashB", 2L), 1L, "hashB", rustIntact = true))
    }
}
