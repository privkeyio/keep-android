package io.privkey.keep.storage

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Coverage for [activePointer], the active-account decision behind
 * `getActiveShareKey`.
 *
 * The two properties worth protecting: it never answers an account the user did
 * not choose when the registry leaves a choice to make, and it never answers
 * past a pointer that is present and unreadable. Both were failures of the
 * resolver this replaces, which pinned the lexicographically lowest group and
 * persisted that guess.
 */
class ActivePointerTest {

    private val a = "aa".repeat(32)
    private val b = "bb".repeat(32)

    /** Every key holds share data. */
    private val allHold: (String) -> Boolean = { true }

    @Test
    fun aValidPointerIsUsed() {
        assertEquals(
            ActivePointer.Use(b),
            activePointer(setOf(a, b), PrefRead.Found(b), allHold),
        )
    }

    @Test
    fun anEmptyRegistryHasNoActiveAccount() {
        assertEquals(ActivePointer.None, activePointer(emptySet(), PrefRead.Found(a), allHold))
    }

    // Present and unreadable is not the same as absent. Scanning past it would
    // answer whichever account sorts first, which is signing as an account the
    // user did not pick.
    @Test
    fun anUnreadablePointerNeverFallsThroughToTheRegistry() {
        assertEquals(
            ActivePointer.None,
            activePointer(setOf(a, b), PrefRead.Unreadable, allHold),
        )
        // Even with a single candidate, which is the tempting case to allow.
        assertEquals(
            ActivePointer.None,
            activePointer(setOf(a), PrefRead.Unreadable, allHold),
        )
    }

    @Test
    fun oneCandidateIsInferredBecauseThereIsNothingToChoose() {
        assertEquals(
            ActivePointer.Use(a),
            activePointer(setOf(a), PrefRead.Absent, allHold),
        )
    }

    // The property keep-mobile's resolve_active_share wants and could not get:
    // with several accounts and no pointer, the answer is none, so the core
    // reaches its "Multiple shares found, please select one" arm instead of
    // standing on a guess.
    @Test
    fun severalCandidatesAndNoPointerIsNotAGuess() {
        assertEquals(
            ActivePointer.None,
            activePointer(setOf(a, b), PrefRead.Absent, allHold),
        )
    }

    @Test
    fun aStalePointerFallsBackToAnUnambiguousCandidate() {
        // Names a group the registry no longer lists.
        assertEquals(
            ActivePointer.Use(a),
            activePointer(setOf(a), PrefRead.Found(b), allHold),
        )
        // Names a listed group whose share data is gone.
        assertEquals(
            ActivePointer.Use(a),
            activePointer(setOf(a, b), PrefRead.Found(b)) { key -> key == a },
        )
    }

    @Test
    fun noCandidateHoldsShareData() {
        assertEquals(
            ActivePointer.None,
            activePointer(setOf(a, b), PrefRead.Absent) { false },
        )
    }

    @Test
    fun aStalePointerWithSeveralCandidatesIsNotAGuess() {
        assertEquals(
            ActivePointer.None,
            activePointer(setOf(a, b), PrefRead.Found("cc".repeat(32)), allHold),
        )
    }
}
