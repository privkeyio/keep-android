package io.privkey.keep

import io.privkey.keep.uniffi.KeepMobileException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ImportFailureMessageTest {

    @Test
    fun aStoredKeyIsNamed() {
        assertEquals(R.string.account_import_already_stored, importFailureMessage(KeepMobileException.KeyAlreadyStored()))
    }

    @Test
    fun theSameShareIsNamed() {
        assertEquals(R.string.account_import_share_stored, importFailureMessage(KeepMobileException.ShareAlreadyStored()))
    }

    @Test
    fun anotherShareOfTheGroupIsNamed() {
        assertEquals(R.string.account_import_other_share_stored, importFailureMessage(KeepMobileException.GroupShareAlreadyStored()))
    }

    @Test
    fun anyOtherFailureStaysGeneric() {
        // The refusal is read from the variant, never from text.
        assertEquals(R.string.account_import_failed, importFailureMessage(KeepMobileException.InvalidShare("This key is already stored")))
        assertEquals(R.string.account_import_failed, importFailureMessage(KeepMobileException.StorageException("This key is already stored")))
        assertEquals(R.string.account_import_failed, importFailureMessage(IllegalStateException()))
    }

    @Test
    fun aDkgRecoveryRefusedOverAStoredShareSaysWhy() {
        assertEquals(R.string.main_pending_dkg_recover_share_stored, dkgRecoveryRefusal(KeepMobileException.ShareAlreadyStored()))
        assertEquals(R.string.account_import_other_share_stored, dkgRecoveryRefusal(KeepMobileException.GroupShareAlreadyStored()))
        assertEquals(R.string.account_import_already_stored, dkgRecoveryRefusal(KeepMobileException.KeyAlreadyStored()))
        assertNull(dkgRecoveryRefusal(KeepMobileException.StorageException("Failed to decrypt share")))
    }
}
