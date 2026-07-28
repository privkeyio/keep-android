package io.privkey.keep.storage

import io.privkey.keep.uniffi.SignPolicySelection
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The UI [SignPolicy] and the core's [SignPolicySelection] must stay aligned: a
 * mis-map would silently move a user onto a looser policy than they chose.
 */
class SignPolicyMappingTest {

    @Test
    fun signPolicyRoundTripsThroughSelection() {
        for (policy in SignPolicy.entries) {
            assertEquals(policy, policy.toSelection().toSignPolicy())
        }
    }

    @Test
    fun selectionRoundTripsThroughSignPolicy() {
        for (selection in SignPolicySelection.entries) {
            assertEquals(selection, selection.toSignPolicy().toSelection())
        }
    }

    @Test
    fun mappingPairsMatchByName() {
        assertEquals(SignPolicySelection.MANUAL, SignPolicy.MANUAL.toSelection())
        assertEquals(SignPolicySelection.BASIC, SignPolicy.BASIC.toSelection())
        assertEquals(SignPolicySelection.AUTO, SignPolicy.AUTO.toSelection())
    }

    /**
     * The core parses the persisted value as an ordinal, so the two enums must agree
     * on ordering, not just on names.
     */
    @Test
    fun ordinalsAgreeAcrossTheBoundary() {
        for (policy in SignPolicy.entries) {
            assertEquals(policy.ordinal, policy.toSelection().ordinal)
        }
    }
}
