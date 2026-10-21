package io.privkey.keep.storage

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.uniffi.KeepMobileException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class StorageFaultCountTest {
    private val storage = AndroidKeystoreStorage(InstrumentationRegistry.getInstrumentation().targetContext)

    @Test
    fun aFailedCallIsCounted() {
        val before = storage.faultsSoFar()
        assertThrows(KeepMobileException.StorageException::class.java) { storage.loadShareByKey("") }
        assertEquals(before + 1, storage.faultsSoFar())
    }

    @Test
    fun aStorageErrorIsCounted() {
        val before = storage.faultsSoFar()
        // A share key outside a request has no cipher to use.
        assertThrows(KeepMobileException.StorageException::class.java) { storage.loadShareByKey("fault_count_test") }
        assertEquals(before + 1, storage.faultsSoFar())
    }

    @Test
    fun anAbsentRecordIsNotAFault() {
        val before = storage.faultsSoFar()
        // Fixed, since each metadata record name gets its own Keystore key.
        assertThrows(KeepMobileException.StorageNotFound::class.java) { storage.loadShareByKey("__keep_fault_count_test") }
        assertEquals(before, storage.faultsSoFar())
    }
}
