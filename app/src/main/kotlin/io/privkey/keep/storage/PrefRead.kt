package io.privkey.keep.storage

import android.content.SharedPreferences

/**
 * What a read of a single stored value found.
 *
 * The typed [SharedPreferences] getters answer with a value plus a caller-supplied
 * default, which gives "nothing is stored" and "something is stored and could not be
 * read" the same answer. That is the right shape for a preference whose default is
 * genuinely correct, and the wrong one for a value that gates authentication or holds
 * the only copy of something: a store holding real values then reports itself as a store
 * holding nothing, and a caller that writes what it believes is a first value destroys
 * what it could not read.
 *
 * A [ReadablePrefs] read is total, and deliberately so. Two different faults reach it:
 * a value that will not decrypt, where the ordinary getter returns the default, and a
 * name that will not resolve, where the getter raises instead, because resolving a name
 * goes through the file's own HMAC key whose decrypt is unguarded. Losing a Keystore
 * alias, which an OS update, a restore to new hardware or a lock-screen change can do,
 * produces the second. Both answer [Unreadable] here, so a caller deciding what to do
 * about an unreadable value never has to also handle an exception from the read.
 *
 * Mirrors the core's [io.privkey.keep.uniffi.StorageRead]. [Unreadable] is what its
 * `Unavailable` becomes when a read crosses the FFI.
 */
sealed interface PrefRead<out T> {
    /**
     * Stored, decrypted and parsed.
     *
     * [toString] is overridden rather than derived: the values this carries include the
     * PIN hash, the database passphrase and share material, and a derived one would put
     * the plaintext into any log line, `check` message or exception that ever
     * interpolates a read. Equality stays derived, which is what tests compare on.
     */
    data class Found<out T>(val value: T) : PrefRead<T> {
        override fun toString(): String = "Found(...)"
    }

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
