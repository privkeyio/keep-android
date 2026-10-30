package io.privkey.keep.storage

import io.privkey.keep.uniffi.KeepMobileException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * The approver state store, with a software wrapping key in place of the Keystore one.
 * The properties the core relies on: only a missing file reads as not found, a store
 * reports Ok only after the directory sync, and a store that fails before the rename
 * leaves the previous file as it was.
 */
class ApproverStateFileTest {

    @get:Rule val tmp = TemporaryFolder()

    private val file: File get() = File(tmp.root, "approver_state")
    private var key: SecretKey? = null
    private val syncs = mutableListOf<File>()
    private var failSync = false

    private fun store() = ApproverStateFile(
        file,
        wrappingKey = { key },
        createWrappingKey = { newKey().also { key = it } },
        syncDir = { dir ->
            syncs += dir
            if (failSync) throw IllegalStateException("sync failed")
        },
    )

    private fun newKey(): SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    @Test
    fun aStoredStateReadsBack() {
        val data = ByteArray(300_000) { it.toByte() }
        store().store(data)
        assertArrayEquals(data, store().load())
        assertEquals(listOf(tmp.root.absoluteFile), syncs)
        assertFalse(File(tmp.root, "approver_state.tmp").exists())
    }

    @Test
    fun theBlobIsNotStoredInTheClear() {
        val data = "freeze counter 42".toByteArray()
        store().store(data)
        assertFalse(String(file.readBytes(), Charsets.ISO_8859_1).contains("freeze counter"))
    }

    @Test
    fun noFileIsNotFound() {
        assertThrows(KeepMobileException.StorageNotFound::class.java) { store().load() }
    }

    @Test
    fun aFileWithoutItsWrappingKeyIsAFaultNotAnAbsence() {
        store().store(byteArrayOf(1, 2, 3))
        key = null
        assertThrows(KeepMobileException.StorageException::class.java) { store().load() }
    }

    @Test
    fun aStoreDoesNotMintANewKeyOverAnExistingFile() {
        store().store(byteArrayOf(1, 2, 3))
        val before = file.readBytes()
        val original = key
        key = null
        assertThrows(KeepMobileException.StorageException::class.java) { store().store(byteArrayOf(4)) }
        assertArrayEquals(before, file.readBytes())
        key = original
        assertArrayEquals(byteArrayOf(1, 2, 3), store().load())
    }

    @Test
    fun aStoreThatFailsBeforeTheRenameLeavesTheOldFile() {
        store().store(byteArrayOf(1, 2, 3))
        val original = key
        key = KeyGenerator.getInstance("HmacSHA256").generateKey()
        assertThrows(Exception::class.java) { store().store(byteArrayOf(9)) }
        key = original
        assertArrayEquals(byteArrayOf(1, 2, 3), store().load())
    }

    @Test
    fun aStoreIsNotOkUntilTheDirectoryIsSynced() {
        failSync = true
        assertThrows(IllegalStateException::class.java) { store().store(byteArrayOf(1)) }
    }

    @Test
    fun aTamperedFileIsAFault() {
        store().store(byteArrayOf(1, 2, 3))
        val blob = file.readBytes()
        blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 1).toByte()
        file.writeBytes(blob)
        assertThrows(Exception::class.java) { store().load() }.also {
            assertFalse(it is KeepMobileException.StorageNotFound)
        }
    }

    @Test
    fun aTruncatedOrUnknownVersionFileIsAFault() {
        store().store(byteArrayOf(1, 2, 3))
        val blob = file.readBytes()
        file.writeBytes(blob.copyOf(20))
        assertThrows(KeepMobileException.StorageException::class.java) { store().load() }
        file.writeBytes(blob.copyOf().also { it[0] = 2 })
        assertThrows(KeepMobileException.StorageException::class.java) { store().load() }
    }

    @Test
    fun deleteRemovesTheStateAndSyncs() {
        store().store(byteArrayOf(1))
        syncs.clear()
        store().delete()
        assertFalse(file.exists())
        assertEquals(listOf(tmp.root.absoluteFile), syncs)
        assertThrows(KeepMobileException.StorageNotFound::class.java) { store().load() }
        store().delete()
        assertTrue(syncs.size == 1)
    }
}
