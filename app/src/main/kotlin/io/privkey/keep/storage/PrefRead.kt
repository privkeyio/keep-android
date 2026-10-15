package io.privkey.keep.storage

import android.content.SharedPreferences

/**
 * What a read of a single stored value found.
 *
 * The typed [SharedPreferences] getters answer with a value plus a caller-supplied
 * default, which gives "nothing is stored" and "something is stored and could not be
 * read" the same answer. That is the right shape for a preference whose default is
 * genuinely correct, and the wrong one for a value that gates authentication or holds
 * the only copy of something: losing a Keystore alias, which an OS update, a restore to
 * new hardware or a lock-screen change can do, leaves the file intact and every value in
 * it undecryptable, so a default-on-fault read reports an intact store as an empty one.
 *
 * Mirrors the core's [io.privkey.keep.uniffi.StorageRead]. [Unreadable] is what its
 * `Unavailable` becomes when a read crosses the FFI.
 */
sealed interface PrefRead<out T> {
    /** Stored, decrypted and parsed. */
    data class Found<out T>(val value: T) : PrefRead<T>

    /** Nothing is stored under this name, so a first use is the honest reading. */
    object Absent : PrefRead<Nothing>

    /**
     * Something is stored and could not be turned into a value.
     *
     * A failed decrypt and a plaintext carrying another type's prefix are folded
     * together: neither is retryable, since the first is permanent for the file once its
     * alias is gone and the second is deterministically wrong, and no caller has a
     * reason to act on them differently. The registry read in [KeystoreEncryptedPrefs]
     * keeps its own malformed case separate because it chooses whether to refold the
     * index, which is a decision no value read makes.
     */
    object Unreadable : PrefRead<Nothing>
}

/**
 * Preferences that will say why a read produced no value.
 *
 * Extends [SharedPreferences] rather than replacing it, so a caller whose default is
 * correct keeps using the ordinary getters and only the call sites that need the
 * distinction take on the extra case. Float is left out because nothing reads one.
 */
interface ReadablePrefs : SharedPreferences {
    fun readString(key: String): PrefRead<String>
    fun readStringSet(key: String): PrefRead<Set<String>>
    fun readInt(key: String): PrefRead<Int>
    fun readLong(key: String): PrefRead<Long>
    fun readBoolean(key: String): PrefRead<Boolean>
}
