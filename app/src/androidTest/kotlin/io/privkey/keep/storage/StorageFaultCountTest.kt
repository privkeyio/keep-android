package io.privkey.keep.storage

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.uniffi.KeepMobileException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

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
    fun anAbsentRecordIsNotAFault() {
        val before = storage.faultsSoFar()
        assertThrows(KeepMobileException.StorageNotFound::class.java) {
            storage.loadShareByKey("__keep_fault_count_test_${UUID.randomUUID()}")
        }
        assertEquals(before, storage.faultsSoFar())
    }
}
