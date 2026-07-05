package io.privkey.keep.nip55

import io.privkey.keep.uniffi.Nip55PermissionDecision
import io.privkey.keep.uniffi.Nip55PermissionDuration
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Round-trip coverage for the Kotlin <-> Rust (uniffi) permission enum mapping seam
 * in PermissionStore.kt (`PermissionDuration.toUniffi`, `Nip55PermissionDuration.toDomain`,
 * `Nip55PermissionDecision.toPermissionDecision`).
 *
 * These `when` mappings are hand-written, one branch per variant. The compiler enforces
 * that every variant is *handled*, but NOT that each branch maps to the *correct* peer:
 * a copy/paste slip (e.g. FOREVER -> ONE_MINUTE, or ALLOW -> DENY) compiles clean and would
 * silently downgrade or misrepresent a granted permission. These tests iterate every variant
 * of every enum (`.entries` / `.values()`) so a newly-added variant is exercised automatically,
 * and assert the mapping is a name-preserving bijection so any wrong branch is caught.
 *
 * The mapping functions are `private` top-level functions; they compile into the
 * `PermissionStoreKt` class and are reached here by reflection rather than by widening their
 * visibility in production. Complements PermissionDecisionTest (string parsing) and
 * PermissionDurationTest (millis/persist semantics), neither of which covers the Rust enum seam.
 */
class PermissionMappingRoundTripTest {

    private val storeKt: Class<*> = Class.forName("io.privkey.keep.nip55.PermissionStoreKt")

    private fun durationToUniffi(d: PermissionDuration): Nip55PermissionDuration {
        val m = storeKt.getDeclaredMethod("toUniffi", PermissionDuration::class.java)
        m.isAccessible = true
        return m.invoke(null, d) as Nip55PermissionDuration
    }

    private fun durationToDomain(r: Nip55PermissionDuration): PermissionDuration {
        val m = storeKt.getDeclaredMethod("toDomain", Nip55PermissionDuration::class.java)
        m.isAccessible = true
        return m.invoke(null, r) as PermissionDuration
    }

    private fun decisionToDomain(r: Nip55PermissionDecision): PermissionDecision {
        val m = storeKt.getDeclaredMethod("toPermissionDecision", Nip55PermissionDecision::class.java)
        m.isAccessible = true
        return m.invoke(null, r) as PermissionDecision
    }

    @Test
    fun `every PermissionDuration maps to same-named Rust variant`() {
        for (d in PermissionDuration.entries) {
            assertEquals("Kotlin->Rust name drift for $d", d.name, durationToUniffi(d).name)
        }
    }

    @Test
    fun `every Rust PermissionDuration maps to same-named Kotlin variant`() {
        for (r in Nip55PermissionDuration.entries) {
            assertEquals("Rust->Kotlin name drift for $r", r.name, durationToDomain(r).name)
        }
    }

    @Test
    fun `PermissionDuration round-trips Kotlin to Rust to Kotlin for every variant`() {
        for (d in PermissionDuration.entries) {
            assertEquals(d, durationToDomain(durationToUniffi(d)))
        }
    }

    @Test
    fun `PermissionDuration round-trips Rust to Kotlin to Rust for every variant`() {
        for (r in Nip55PermissionDuration.entries) {
            assertEquals(r, durationToUniffi(durationToDomain(r)))
        }
    }

    @Test
    fun `PermissionDuration mapping covers the full enum on both sides`() {
        assertEquals(
            "PermissionDuration variant count differs between Kotlin and Rust",
            PermissionDuration.entries.size,
            Nip55PermissionDuration.entries.size
        )
    }

    @Test
    fun `every Rust PermissionDecision maps to same-named Kotlin variant`() {
        // Only the Rust->Kotlin direction has an explicit mapping function; assert it is a
        // total, name-preserving map so no valid decision (e.g. ALLOW) is silently downgraded.
        for (r in Nip55PermissionDecision.entries) {
            assertEquals("Rust->Kotlin decision drift for $r", r.name, decisionToDomain(r).name)
        }
    }

    @Test
    fun `PermissionDecision mapping covers the full enum on both sides`() {
        assertEquals(
            "PermissionDecision variant count differs between Kotlin and Rust",
            PermissionDecision.entries.size,
            Nip55PermissionDecision.entries.size
        )
    }
}
