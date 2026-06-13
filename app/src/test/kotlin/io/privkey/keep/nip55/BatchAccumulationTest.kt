package io.privkey.keep.nip55

import io.privkey.keep.uniffi.Nip55RequestType
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Regression coverage for the NIP-55 batch grouping rules (gh #323), which gate
 * which requests get folded into a single approval. Decisions only; the Activity
 * flow (biometric/FROST/result codes) is native-bound and out of unit scope.
 */
class BatchAccumulationTest {

    private val app = "com.test.app"
    private val cap = 20

    private fun decide(
        pending: List<Nip55RequestType>,
        pendingCaller: String?,
        newType: Nip55RequestType,
        newCaller: String = app
    ) = batchAccumulationDecision(pending, pendingCaller, newType, newCaller, cap)

    @Test
    fun firstRequestResets() {
        // Empty pending: nothing to accumulate into, so the request starts a batch.
        assertEquals(
            BatchAccumulation.RESET,
            decide(emptyList(), pendingCaller = null, newType = Nip55RequestType.SIGN_EVENT)
        )
    }

    @Test
    fun sameCallerOperationAccumulates() {
        assertEquals(
            BatchAccumulation.ACCUMULATE,
            decide(listOf(Nip55RequestType.SIGN_EVENT), app, Nip55RequestType.SIGN_EVENT)
        )
    }

    @Test
    fun encryptDecryptMixAccumulatesForSameCaller() {
        assertEquals(
            BatchAccumulation.ACCUMULATE,
            decide(listOf(Nip55RequestType.SIGN_EVENT, Nip55RequestType.NIP44_ENCRYPT), app, Nip55RequestType.NIP44_DECRYPT)
        )
    }

    @Test
    fun differentCallerResets() {
        assertEquals(
            BatchAccumulation.RESET,
            decide(listOf(Nip55RequestType.SIGN_EVENT), pendingCaller = app, newType = Nip55RequestType.SIGN_EVENT, newCaller = "com.other.app")
        )
    }

    @Test
    fun newGetPublicKeyNeverBatches() {
        assertEquals(
            BatchAccumulation.RESET,
            decide(listOf(Nip55RequestType.SIGN_EVENT), app, Nip55RequestType.GET_PUBLIC_KEY)
        )
    }

    @Test
    fun pendingGetPublicKeyIsNeverBatchedInto() {
        assertEquals(
            BatchAccumulation.RESET,
            decide(listOf(Nip55RequestType.GET_PUBLIC_KEY), app, Nip55RequestType.SIGN_EVENT)
        )
    }

    @Test
    fun atCapDropsOverflow() {
        val full = List(cap) { Nip55RequestType.SIGN_EVENT }
        assertEquals(
            BatchAccumulation.DROP_OVER_CAP,
            decide(full, app, Nip55RequestType.SIGN_EVENT)
        )
    }

    @Test
    fun oneBelowCapStillAccumulates() {
        val nearFull = List(cap - 1) { Nip55RequestType.SIGN_EVENT }
        assertEquals(
            BatchAccumulation.ACCUMULATE,
            decide(nearFull, app, Nip55RequestType.SIGN_EVENT)
        )
    }
}
