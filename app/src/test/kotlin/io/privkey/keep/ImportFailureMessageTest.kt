package io.privkey.keep

import io.privkey.keep.uniffi.KeepMobileException
import org.junit.Assert.assertEquals
import org.junit.Test

class ImportFailureMessageTest {

    @Test
    fun aStoredKeyIsNamed() {
        assertEquals(
            R.string.account_import_already_stored,
            importFailureMessage(KeepMobileException.InvalidShare("This key is already stored"))
        )
    }

    @Test
    fun anotherShareOfTheGroupIsNamed() {
        assertEquals(
            R.string.account_import_other_share_stored,
            importFailureMessage(KeepMobileException.InvalidShare("Another share of this group is already stored"))
        )
    }

    @Test
    fun anyOtherFailureStaysGeneric() {
        assertEquals(R.string.account_import_failed, importFailureMessage(KeepMobileException.InvalidShare("bad checksum")))
        assertEquals(R.string.account_import_failed, importFailureMessage(KeepMobileException.StorageException("This key is already stored")))
        assertEquals(R.string.account_import_failed, importFailureMessage(IllegalStateException()))
    }
}
