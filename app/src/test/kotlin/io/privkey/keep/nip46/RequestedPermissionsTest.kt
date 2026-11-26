package io.privkey.keep.nip46

import org.junit.Assert.assertEquals
import org.junit.Test

class RequestedPermissionsTest {

    @Test
    fun splitsMethodsAndKinds() {
        assertEquals(
            listOf("get_public_key" to null, "sign_event" to "1", "nip44_encrypt" to null),
            requestedPermissions("get_public_key, sign_event:1,,nip44_encrypt"),
        )
    }

    @Test
    fun nothingRequestedShowsNoRows() {
        assertEquals(emptyList<Pair<String, String?>>(), requestedPermissions(null))
        assertEquals(emptyList<Pair<String, String?>>(), requestedPermissions(" , "))
    }

    @Test
    fun controlCharactersAndLengthAreStrippedForDisplay() {
        val (method, kind) = requestedPermissions("sign‮event:1\u0000" + "9".repeat(80)).single()
        assertEquals("signevent", method)
        assertEquals(50, kind!!.length)
    }
}
