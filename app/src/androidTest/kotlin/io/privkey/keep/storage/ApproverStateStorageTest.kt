package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.ApproverHandler
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.ShareMetadataInfo
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore

/**
 * The approver's key, `__keep_approver`, through the real storage and Keystore: it lands
 * in its own file rather than a prefs entry, and a file whose wrapping key is gone is a
 * fault the core will not mistake for no state.
 */
@RunWith(AndroidJUnit4::class)
class ApproverStateStorageTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private val file: File get() = File(context.noBackupFilesDir, "approver_state$SUFFIX")
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @Before fun setup() = wipe()
    @After fun teardown() = wipe()

    private fun wipe() {
        file.delete()
        File(context.noBackupFilesDir, "approver_state$SUFFIX.tmp").delete()
        if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS)
    }

    private fun storage() = AndroidKeystoreStorage(
        context,
        requireUserAuth = false,
        keystoreAlias = "keep_frost_share$SUFFIX",
        prefsSuffix = SUFFIX
    )

    private val metadata = ShareMetadataInfo(
        name = "approver",
        identifier = 0u,
        threshold = 0u,
        totalShares = 0u,
        groupPubkey = ByteArray(0),
        didBackup = false
    )

    @Test
    fun theStateRoundTripsThroughItsOwnFile() {
        val data = ByteArray(350_000) { (it * 7).toByte() }
        storage().storeShareByKey(KEY, data, metadata)
        assertTrue(file.exists())
        assertTrue(keyStore.containsAlias(ALIAS))
        assertArrayEquals(data, storage().loadShareByKey(KEY))
    }

    @Test
    fun aLostWrappingKeyIsAFaultAndBlocksAStore() {
        storage().storeShareByKey(KEY, byteArrayOf(1, 2, 3), metadata)
        keyStore.deleteEntry(ALIAS)
        assertThrows(KeepMobileException.StorageException::class.java) { storage().loadShareByKey(KEY) }
        assertThrows(KeepMobileException.StorageException::class.java) {
            storage().storeShareByKey(KEY, byteArrayOf(4), metadata)
        }
        assertTrue(file.exists())
        assertFalse(keyStore.containsAlias(ALIAS))
    }

    @Test
    fun deleteLeavesNothingAndIsNotFoundAfterwards() {
        storage().storeShareByKey(KEY, byteArrayOf(1), metadata)
        storage().deleteShareByKey(KEY)
        assertFalse(file.exists())
        assertThrows(KeepMobileException.StorageNotFound::class.java) { storage().loadShareByKey(KEY) }
        storage().deleteShareByKey(KEY)
    }

    @Test
    fun anUnreadableStateIsAStorageFaultUntilItIsDeleted() {
        storage().storeShareByKey(KEY, "not the approver state".toByteArray(), metadata)
        assertUnreadable()
        assertEquals(ApproverStateFile.Check.READABLE, storage().checkApproverState())
        keyStore.deleteEntry(ALIAS)
        assertUnreadable()
        assertEquals(ApproverStateFile.Check.DAMAGED, storage().checkApproverState())
        storage().deleteShareByKey(KEY)
        assertEquals(ApproverStateFile.Check.ABSENT, storage().checkApproverState())
        val handler = ApproverHandler(KeepMobile(storage()))
        assertFalse(handler.status().paired)
        assertFalse(file.exists())
    }

    @Test
    fun deleteDropsTheWrappingKey() {
        storage().storeShareByKey(KEY, byteArrayOf(1), metadata)
        assertTrue(keyStore.containsAlias(ALIAS))
        storage().deleteShareByKey(KEY)
        assertFalse(keyStore.containsAlias(ALIAS))
    }

    private fun assertUnreadable() {
        assertThrows(KeepMobileException.StorageException::class.java) { ApproverHandler(KeepMobile(storage())) }
        assertTrue(file.exists())
    }

    private companion object {
        const val KEY = "__keep_approver"
        const val SUFFIX = "_approver_test"
        const val ALIAS = "keep_approver_wrap$SUFFIX"
    }
}
