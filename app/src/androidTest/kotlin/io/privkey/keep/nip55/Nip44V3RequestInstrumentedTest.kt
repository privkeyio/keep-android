package io.privkey.keep.nip55

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Nip44V3RequestInstrumentedTest {

    private fun request(
        type: Nip55RequestType,
        content: String = "",
        kind: UInt? = null,
        scope: String? = null
    ) = Nip55Request(
        requestType = type,
        content = content,
        pubkey = null,
        returnType = "signature",
        compressionType = "none",
        callbackUrl = null,
        id = null,
        currentUser = null,
        permissions = null,
        kind = kind,
        scope = scope
    )

    @Test
    fun isNip44V3_trueOnlyForV3Variants() {
        assertTrue(Nip55RequestType.NIP44_V3_ENCRYPT.isNip44V3())
        assertTrue(Nip55RequestType.NIP44_V3_DECRYPT.isNip44V3())
        assertFalse(Nip55RequestType.NIP44_ENCRYPT.isNip44V3())
        assertFalse(Nip55RequestType.NIP44_DECRYPT.isNip44V3())
        assertFalse(Nip55RequestType.SIGN_EVENT.isNip44V3())
        assertFalse(Nip55RequestType.GET_PUBLIC_KEY.isNip44V3())
    }

    @Test
    fun eventKind_returnsCarriedKindForV3() {
        assertEquals(1059, request(Nip55RequestType.NIP44_V3_ENCRYPT, kind = 1059u).eventKind())
        assertEquals(4, request(Nip55RequestType.NIP44_V3_DECRYPT, kind = 4u).eventKind())
    }

    @Test
    fun eventKind_nullWhenV3KindMissing() {
        assertNull(request(Nip55RequestType.NIP44_V3_ENCRYPT, kind = null).eventKind())
    }

    @Test
    fun eventKind_parsesSignEventContentAndIgnoresCarriedKind() {
        assertEquals(1, request(Nip55RequestType.SIGN_EVENT, content = """{"kind":1}""").eventKind())
    }

    @Test
    fun eventKind_nullForNonV3EncryptRegardlessOfCarriedKind() {
        assertNull(request(Nip55RequestType.NIP44_ENCRYPT, kind = 7u).eventKind())
    }
}
