package io.privkey.keep.nip55

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EventKindsInstrumentedTest {

    @Test
    fun isSensitiveKindReturnsTrueForMetadataKind0() {
        assertTrue(isSensitiveKind(0))
    }

    @Test
    fun isSensitiveKindReturnsTrueForContactsKind3() {
        assertTrue(isSensitiveKind(3))
    }

    @Test
    fun isSensitiveKindReturnsTrueForEncryptedDmKind4() {
        assertTrue(isSensitiveKind(4))
    }

    @Test
    fun isSensitiveKindReturnsTrueForGiftWrapKind1059() {
        assertTrue(isSensitiveKind(1059))
    }

    @Test
    fun isSensitiveKindReturnsTrueForReportKind1984() {
        assertTrue(isSensitiveKind(1984))
    }

    @Test
    fun isSensitiveKindReturnsTrueForMuteListKind10000() {
        assertTrue(isSensitiveKind(10000))
    }

    @Test
    fun isSensitiveKindReturnsTrueForRelayListMetadataKind10002() {
        assertTrue(isSensitiveKind(10002))
    }

    @Test
    fun isSensitiveKindReturnsTrueForBookmarkListKind10003() {
        assertTrue(isSensitiveKind(10003))
    }

    @Test
    fun isSensitiveKindReturnsTrueForSearchRelayListKind10004() {
        assertTrue(isSensitiveKind(10004))
    }

    @Test
    fun isSensitiveKindReturnsTrueForBlockedRelaysListKind10006() {
        assertTrue(isSensitiveKind(10006))
    }

    @Test
    fun isSensitiveKindReturnsTrueForDmRelayListKind10050() {
        assertTrue(isSensitiveKind(10050))
    }

    @Test
    fun isSensitiveKindReturnsTrueForReplaceableEvents() {
        assertTrue(isSensitiveKind(30000))
        assertTrue(isSensitiveKind(30023))
        assertTrue(isSensitiveKind(35000))
        assertTrue(isSensitiveKind(39999))
    }

    @Test
    fun isSensitiveKindReturnsFalseForRegularTextNoteKind1() {
        assertFalse(isSensitiveKind(1))
    }

    @Test
    fun isSensitiveKindReturnsFalseForReactionKind7() {
        assertFalse(isSensitiveKind(7))
    }

    @Test
    fun isSensitiveKindReturnsFalseForRepostKind6() {
        assertFalse(isSensitiveKind(6))
    }

    @Test
    fun isSensitiveKindReturnsFalseForOutsideReplaceableRange() {
        assertFalse(isSensitiveKind(29999))
        assertFalse(isSensitiveKind(40000))
    }

    @Test
    fun isSensitiveKindReturnsTrueForNegativeKinds() {
        assertTrue(isSensitiveKind(-1))
        assertTrue(isSensitiveKind(Int.MIN_VALUE))
    }

    @Test
    fun sensitiveKindWarningReturnsWarningForSensitiveKinds() {
        assertNotNull(sensitiveKindWarning(0))
        assertNotNull(sensitiveKindWarning(3))
        assertNotNull(sensitiveKindWarning(4))
        assertNotNull(sensitiveKindWarning(1059))
        assertNotNull(sensitiveKindWarning(1984))
        assertNotNull(sensitiveKindWarning(10000))
        assertNotNull(sensitiveKindWarning(10002))
        assertNotNull(sensitiveKindWarning(10003))
        assertNotNull(sensitiveKindWarning(10004))
        assertNotNull(sensitiveKindWarning(10006))
        assertNotNull(sensitiveKindWarning(10050))
    }

    @Test
    fun sensitiveKindWarningReturnsWarningForReplaceableEvents() {
        assertNotNull(sensitiveKindWarning(30000))
        assertNotNull(sensitiveKindWarning(35000))
        assertNotNull(sensitiveKindWarning(39999))
    }

    @Test
    fun sensitiveKindWarningReturnsNullForNonSensitiveKinds() {
        assertNull(sensitiveKindWarning(1))
        assertNull(sensitiveKindWarning(7))
        assertNull(sensitiveKindWarning(6))
    }

    @Test
    fun sensitiveKindWarningContainsRelevantInfoForMetadata() {
        val warning = sensitiveKindWarning(0)
        assertNotNull(warning)
        assertTrue(warning!!.contains("profile") || warning.contains("Metadata"))
    }

    @Test
    fun sensitiveKindWarningContainsRelevantInfoForContacts() {
        val warning = sensitiveKindWarning(3)
        assertNotNull(warning)
        assertTrue(warning!!.contains("contacts") || warning.contains("follow"))
    }

    @Test
    fun sensitiveKindWarningContainsRelevantInfoForEncryptedDm() {
        val warning = sensitiveKindWarning(4)
        assertNotNull(warning)
        assertTrue(warning!!.contains("private") || warning.contains("Encrypted"))
    }

    @Test
    fun sensitiveKindWarningReturnsWarningForNegativeKinds() {
        assertEquals("Invalid event kind", sensitiveKindWarning(-1))
        assertEquals("Invalid event kind", sensitiveKindWarning(Int.MIN_VALUE))
    }
}
