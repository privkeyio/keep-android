package io.privkey.keep

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * When an import or DKG has to be cleaned up after as an account switch. Missing one
 * leaves the previous account's grants applying to the new key; the cost of a spurious
 * one is only that those grants are revoked.
 */
class StoreSwitchedAccountTest {

    @Test
    fun replacingTheActiveAccountIsASwitch() {
        assertTrue(storeSwitchedAccount(hadShare = true, activeBefore = A, activeAfter = B))
    }

    @Test
    fun aStoreThatLeftTheActiveAccountAloneIsNot() {
        assertFalse(storeSwitchedAccount(hadShare = true, activeBefore = A, activeAfter = A))
    }

    @Test
    fun theFirstAccountHasNothingToCleanUpAfter() {
        assertFalse(storeSwitchedAccount(hadShare = false, activeBefore = null, activeAfter = B))
    }

    @Test
    fun aPointerThatCannotBeReadAfterwardsCountsAsAChange() {
        assertTrue(storeSwitchedAccount(hadShare = true, activeBefore = A, activeAfter = null))
    }

    @Test
    fun anAccountActiveWithoutAPointerIsReplacedByOneThatHasOne() {
        assertTrue(storeSwitchedAccount(hadShare = true, activeBefore = null, activeAfter = B))
    }

    private companion object {
        const val A = "aa"
        const val B = "bb"
    }
}
