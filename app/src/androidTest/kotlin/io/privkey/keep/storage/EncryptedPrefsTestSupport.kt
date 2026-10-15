package io.privkey.keep.storage

import android.content.Context
import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue

/**
 * Staging for the fault a store cannot distinguish on its own: a value that is on disk
 * and will not decrypt.
 *
 * Kept in one place because finding the entry to break is not obvious. Names are stored
 * hashed, and the file also holds its own HMAC key and a registry under hashed names, so
 * an entry cannot be located by the plaintext key it was written under. What identifies
 * it is being the one entry a write adds once everything else already exists.
 */
internal fun rawPrefs(context: Context, prefsName: String) =
    context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)

/** The stored name [write] lands on, identified by what it adds. */
internal fun writeAndFindStoredName(context: Context, prefsName: String, write: () -> Unit): String {
    KeystoreEncryptedPrefs.create(context, prefsName).edit().putString(ANCHOR_KEY, "0").commit()
    val before = rawPrefs(context, prefsName).all.keys.toSet()
    write()
    val added = rawPrefs(context, prefsName).all.keys.toSet() - before
    assertEquals("expected exactly one new stored entry: $added", 1, added.size)
    return added.first()
}

/**
 * Breaks one value the way a lost Keystore alias breaks every value: the last byte of the
 * ciphertext is flipped, so the IV and body stay well formed and the failure is the GCM
 * tag check rather than a length or decode error on a different branch.
 */
internal fun corruptStoredValue(context: Context, prefsName: String, storedName: String) {
    val raw = rawPrefs(context, prefsName)
    val stored = raw.getString(storedName, null)!!
    assertTrue(
        "this flips a byte of the body, so the value has to carry the marker it is written with",
        stored.startsWith(BOUND_PREFIX)
    )
    val bytes = Base64.decode(stored.removePrefix(BOUND_PREFIX), Base64.NO_WRAP)
    bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
    raw.edit()
        .putString(storedName, BOUND_PREFIX + Base64.encodeToString(bytes, Base64.NO_WRAP))
        .commit()
}

private const val ANCHOR_KEY = "__test_anchor__"

/** The marker KeystoreEncryptedPrefs puts on a value bound to its key name. */
internal const val BOUND_PREFIX = "v2:"
