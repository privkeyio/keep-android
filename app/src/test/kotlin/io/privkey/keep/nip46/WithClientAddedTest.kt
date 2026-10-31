package io.privkey.keep.nip46

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class WithClientAddedTest {

    private val full = List(BunkerService.MAX_AUTHORIZED_CLIENTS) { "%064x".format(it) }

    @Test
    fun aNewClientIsAppended() {
        assertEquals(listOf(A, B), BunkerService.withClientAdded(listOf(A), B))
    }

    @Test
    fun aKnownClientLeavesTheListAsItWas() {
        assertEquals(listOf(A), BunkerService.withClientAdded(listOf(A), A.uppercase()))
    }

    // Evicting the oldest left its engine grants live, so a full list refuses instead.
    @Test
    fun aFullListRefusesANewClientAndEvictsNobody() {
        assertNull(BunkerService.withClientAdded(full, B))
    }

    @Test
    fun aFullListStillTakesBackAClientItHolds() {
        assertEquals(full, BunkerService.withClientAdded(full, full.first()))
    }

    @Test
    fun aListWithinTheCapHasNothingOverIt() {
        assertEquals(emptyList<String>(), BunkerService.clientsOverCap(full))
    }

    @Test
    fun theOldestClientsPastTheCapAreOverIt() {
        assertEquals(listOf(A, B), BunkerService.clientsOverCap(listOf(A, B) + full))
    }

    private companion object {
        const val A = "aa00000000000000000000000000000000000000000000000000000000000000"
        const val B = "bb00000000000000000000000000000000000000000000000000000000000000"
    }
}
