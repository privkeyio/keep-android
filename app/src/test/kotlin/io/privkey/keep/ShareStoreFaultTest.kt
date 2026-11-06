package io.privkey.keep

import io.privkey.keep.uniffi.ShareStoreStatus
import org.junit.Assert.assertEquals
import org.junit.Test

class ShareStoreFaultTest {

    private val a = "a".repeat(64)
    private val b = "b".repeat(64)

    @Test
    fun onlySomeUnreadableNamesGroups() {
        assertEquals(emptyList<String>(), unreadableGroups(ShareStoreStatus.Readable))
        assertEquals(emptyList<String>(), unreadableGroups(ShareStoreStatus.Unavailable))
        assertEquals(listOf(a, b), unreadableGroups(ShareStoreStatus.SomeUnreadable(listOf(a, b))))
    }

    @Test
    fun removeIsOfferedOnlyAfterARetryFails() {
        val failed = afterRetry(emptySet(), listOf(a), ShareStoreStatus.SomeUnreadable(listOf(a, b)))
        assertEquals("b was not retried, so it is not offered for removal yet", setOf(a), failed)
    }

    @Test
    fun aShareThatReadsAgainIsNoLongerOfferedForRemoval() {
        val failed = afterRetry(setOf(a, b), listOf(a, b), ShareStoreStatus.SomeUnreadable(listOf(b)))
        assertEquals(setOf(b), failed)
        assertEquals(emptySet<String>(), afterRetry(setOf(a), listOf(a), ShareStoreStatus.Readable))
    }

    @Test
    fun anUnavailableRegistryOffersNoRemoval() {
        assertEquals(emptySet<String>(), afterRetry(setOf(a), listOf(a), ShareStoreStatus.Unavailable))
    }

    @Test
    fun shortGroupKeepsBothEnds() {
        assertEquals("aaaaaaaa…bbbbbbbb", shortGroup("a".repeat(32) + "b".repeat(32)))
        assertEquals("abc", shortGroup("abc"))
    }
}
