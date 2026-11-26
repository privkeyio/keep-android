package io.privkey.keep.nip46

import org.junit.Assert.assertEquals
import org.junit.Test

class RequestedPermissionsTest {

    @Test
    fun listsEachMethodOnceWithoutKinds() {
        assertEquals(
            listOf("get_public_key", "sign_event", "nip44_encrypt"),
            requestedPermissions("get_public_key, sign_event:1,,sign_event:7,nip44_encrypt"),
        )
    }

    @Test
    fun nothingRequestedShowsNoRows() {
        assertEquals(emptyList<String>(), requestedPermissions(null))
        assertEquals(emptyList<String>(), requestedPermissions(" , "))
    }

    @Test
    fun controlCharactersAndLengthAreStrippedForDisplay() {
        assertEquals(listOf("signevent"), requestedPermissions("sign\u202Eevent:1"))
        assertEquals(50, requestedPermissions("x".repeat(80)).single().length)
    }
}
