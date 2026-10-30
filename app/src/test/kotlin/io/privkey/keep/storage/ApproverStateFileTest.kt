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
    private val replacedBeforeSync = mutableListOf<Boolean>()
    private var failSync = false

    private fun store() = ApproverStateFile(
        file,
        wrappingKey = { key },
        createWrappingKey = { newKey().also { key = it } },
        deleteWrappingKey = { key = null },
        syncDir = { dir ->
            syncs += dir
            replacedBeforeSync += !File(tmp.root, "approver_state.tmp").exists()
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
        assertEquals(listOf(true), replacedBeforeSync)
        assertFalse(File(tmp.root, "approver_state.tmp").exists())
    }

    @Test
    fun aRenameThatFailsLeavesTheTargetAndNoTempFile() {
        key = newKey()
        file.mkdir()
        File(file, "child").writeBytes(byteArrayOf(7))
        assertThrows(KeepMobileException.StorageException::class.java) { store().store(byteArrayOf(1)) }
        assertArrayEquals(byteArrayOf(7), File(file, "child").readBytes())
        assertFalse(File(tmp.root, "approver_state.tmp").exists())
        assertTrue(syncs.isEmpty())
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
        assertEquals(2, syncs.size)
    }

    @Test
    fun deleteAlsoDropsTheWrappingKeySoTheNextStoreMintsOne() {
        store().store(byteArrayOf(1))
        val original = key
        store().delete()
        assertEquals(null, key)
        store().store(byteArrayOf(2))
        assertFalse(key == original)
        assertArrayEquals(byteArrayOf(2), store().load())
    }

    @Test
    fun aLoadRecordsDamageApartFromAFaultThatMayClear() {
        val state = store()
        fun loaded(): ApproverStateFile.LoadResult? {
            runCatching { state.load() }
            return state.lastLoad
        }
        assertEquals(ApproverStateFile.LoadResult.ABSENT, loaded())
        state.store(byteArrayOf(1, 2, 3))
        assertEquals(ApproverStateFile.LoadResult.READABLE, loaded())
        val original = key
        key = KeyGenerator.getInstance("HmacSHA256").generateKey()
        assertEquals(ApproverStateFile.LoadResult.FAULT, loaded())
        key = null
        assertEquals(ApproverStateFile.LoadResult.DAMAGED, loaded())
        key = newKey()
        assertEquals(ApproverStateFile.LoadResult.DAMAGED, loaded())
        key = original
        val blob = file.readBytes()
        file.writeBytes(blob.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() })
        assertEquals(ApproverStateFile.LoadResult.DAMAGED, loaded())
        file.writeBytes(blob.copyOf(20))
        assertEquals(ApproverStateFile.LoadResult.DAMAGED, loaded())
        file.delete()
        file.mkdir()
        assertEquals(ApproverStateFile.LoadResult.FAULT, loaded())
    }

    @Test
    fun deleteRemovesATempFileACrashedStoreLeft() {
        store().store(byteArrayOf(1))
        File(tmp.root, "approver_state.tmp").writeBytes(byteArrayOf(2))
        store().delete()
        assertFalse(File(tmp.root, "approver_state.tmp").exists())
    }
}
