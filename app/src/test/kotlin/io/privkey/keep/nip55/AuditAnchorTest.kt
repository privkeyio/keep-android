package io.privkey.keep.nip55

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Coverage for the audit-chain tail anchor (gh #308), which hardens the Rust
 * keyed-HMAC walk against tail truncation (newest rows deleted) and head
 * fabrication (legacy rows prepended) by an attacker with Room write access.
 * Anchor persistence is Keystore-backed and native-bound; only the pure
 * reconciliation decision is unit-tested here.
 */
class AuditAnchorTest {

    private val valid = ChainVerificationResult.Valid

    @Test
    fun cleanChainMatchingAnchorIsValid() {
        assertEquals(
            ChainVerificationResult.Valid,
            resolveChainVerification(AuditAnchor("hashB", 2L), 2L, "hashB", 2L, valid)
        )
    }

    @Test
    fun tailTruncationByCountIsTruncated() {
        // Newest row deleted: fewer rows than the anchor recorded.
        assertEquals(
            ChainVerificationResult.Truncated(1L),
            resolveChainVerification(AuditAnchor("hashB", 2L), 1L, "hashA", 1L, valid)
        )
    }

    @Test
    fun tailTruncationByHashIsTruncated() {
        // Same count but the most-recent hash no longer matches the anchor.
        assertEquals(
            ChainVerificationResult.Truncated(2L),
            resolveChainVerification(AuditAnchor("hashB", 2L), 2L, "hashX", 2L, valid)
        )
    }

    @Test
    fun headFabricationGrowingCountIsTampered() {
        // Prepended legacy rows: count grows; the Rust walk excuses them as legacy.
        assertEquals(
            ChainVerificationResult.Tampered(3L),
            resolveChainVerification(
                AuditAnchor("hashB", 2L), 3L, "hashB", 3L,
                ChainVerificationResult.PartiallyVerified(1)
            )
        )
    }

    @Test
    fun firstRunWithoutAnchorDefersToRust() {
        assertEquals(valid, resolveChainVerification(null, 2L, "hashB", 2L, valid))
    }

    @Test
    fun emptyDbWithZeroAnchorIsValid() {
        assertEquals(
            ChainVerificationResult.Valid,
            resolveChainVerification(AuditAnchor("", 0L), 0L, "", 0L, valid)
        )
    }

    @Test
    fun rustTamperedIsNotDowngraded() {
        // An anchor match must not mask a tamper the Rust walk already found.
        assertEquals(
            ChainVerificationResult.Tampered(2L),
            resolveChainVerification(
                AuditAnchor("hashB", 2L), 2L, "hashB", 2L,
                ChainVerificationResult.Tampered(2L)
            )
        )
    }

    @Test
    fun rustBrokenIsNotDowngraded() {
        assertEquals(
            ChainVerificationResult.Broken(2L),
            resolveChainVerification(
                AuditAnchor("hashB", 2L), 1L, "hashA", 1L,
                ChainVerificationResult.Broken(2L)
            )
        )
    }

    @Test
    fun partiallyVerifiedWithMatchingAnchorIsPreserved() {
        val partial = ChainVerificationResult.PartiallyVerified(1)
        assertEquals(
            partial,
            resolveChainVerification(AuditAnchor("hashB", 3L), 3L, "hashB", 3L, partial)
        )
    }
}
