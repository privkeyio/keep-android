package io.privkey.keep.storage

import android.system.Os
import android.system.OsConstants
import io.privkey.keep.uniffi.KeepMobileException
import java.io.File
import java.io.FileOutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The approver's state, kept in its own file instead of a prefs entry.
 *
 * The core saves a freeze counter here before it sends the freeze, and only once the
 * save returned Ok, so Ok has to mean durable: a rolled-back counter is reused and the
 * gateway refuses the freeze. A prefs commit cannot promise that, since it never syncs
 * the directory and a power loss can restore the previous file. A store writes a temp
 * file, syncs it, renames it over the old one and syncs the directory, and returns
 * only after all four. A store that fails before the rename leaves the old file as it
 * was. One that fails after it has the new state in place but reports the error,
 * which is safe, since the core sends nothing on an error.
 *
 * The blob is sealed under a fresh AES-GCM key in software, and only that key is
 * wrapped by the Keystore key, so a StrongBox key handles 32 bytes per write instead
 * of the whole state.
 *
 * A file whose wrapping key is gone is a fault, not an absence. The core answers
 * absence by letting the owner pair again, which would overwrite state that is only
 * unreadable, so only a missing file reads as not found, and a store refuses to mint
 * a new wrapping key over an existing file.
 */
internal class ApproverStateFile(
    private val file: File,
    private val wrappingKey: () -> SecretKey?,
    private val createWrappingKey: () -> SecretKey,
    private val syncDir: (File) -> Unit = ::fsyncDir,
) {
    private val dir: File get() = file.absoluteFile.parentFile!!
    private val temp: File get() = File(dir, "${file.name}.tmp")

    @Synchronized
    fun store(data: ByteArray) {
        val key = wrappingKey() ?: run {
            if (file.exists()) throw KeepMobileException.StorageException(
                "the approver state is stored but its wrapping key is missing"
            )
            createWrappingKey()
        }
        val sealed = seal(key, data)
        try {
            FileOutputStream(temp).use { out ->
                out.write(sealed)
                out.fd.sync()
            }
            if (!temp.renameTo(file)) throw KeepMobileException.StorageException("the approver state could not be replaced")
        } catch (e: Exception) {
            temp.delete()
            throw e
        }
        syncDir(dir)
    }

    @Synchronized
    fun load(): ByteArray {
        if (!file.exists()) throw KeepMobileException.StorageNotFound()
        val blob = file.readBytes()
        val key = wrappingKey() ?: throw KeepMobileException.StorageException(
            "the approver state is stored but its wrapping key is missing"
        )
        if (blob.size < HEADER_SIZE + TAG_SIZE || blob[0] != VERSION) {
            throw KeepMobileException.StorageException("the approver state is malformed")
        }
        val dek = Cipher.getInstance(GCM).run {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, blob, 1, IV_SIZE))
            doFinal(blob, 1 + IV_SIZE, WRAPPED_SIZE)
        }
        try {
            return Cipher.getInstance(GCM).run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(dek, "AES"), GCMParameterSpec(TAG_BITS, blob, HEADER_SIZE - IV_SIZE, IV_SIZE))
                doFinal(blob, HEADER_SIZE, blob.size - HEADER_SIZE)
            }
        } finally {
            dek.fill(0)
        }
    }

    @Synchronized
    fun delete() {
        if (!file.exists()) return
        if (!file.delete()) throw KeepMobileException.StorageException("the approver state could not be deleted")
        syncDir(dir)
    }

    private fun seal(key: SecretKey, data: ByteArray): ByteArray {
        val dek = ByteArray(DEK_SIZE).also { SecureRandom().nextBytes(it) }
        try {
            val wrap = Cipher.getInstance(GCM).apply { init(Cipher.ENCRYPT_MODE, key) }
            val wrapped = wrap.doFinal(dek)
            val body = Cipher.getInstance(GCM).apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(dek, "AES")) }
            val sealed = body.doFinal(data)
            check(wrap.iv.size == IV_SIZE && body.iv.size == IV_SIZE && wrapped.size == WRAPPED_SIZE) {
                "unexpected AES-GCM output size"
            }
            return byteArrayOf(VERSION) + wrap.iv + wrapped + body.iv + sealed
        } finally {
            dek.fill(0)
        }
    }

    private companion object {
        const val GCM = "AES/GCM/NoPadding"
        const val VERSION: Byte = 1
        const val IV_SIZE = 12
        const val TAG_BITS = 128
        const val TAG_SIZE = TAG_BITS / 8
        const val DEK_SIZE = 32
        const val WRAPPED_SIZE = DEK_SIZE + TAG_SIZE
        // Version, wrap IV, wrapped key, body IV. The sealed body follows.
        const val HEADER_SIZE = 1 + IV_SIZE + WRAPPED_SIZE + IV_SIZE

        fun fsyncDir(dir: File) {
            val fd = Os.open(dir.path, OsConstants.O_RDONLY, 0)
            try {
                Os.fsync(fd)
            } finally {
                Os.close(fd)
            }
        }
    }
}
