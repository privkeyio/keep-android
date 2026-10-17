package io.privkey.keep.storage

import android.content.Context
import android.util.Base64
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
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

/**
 * Removes what [writeAndFindStoredName] stages, which a file the app itself reads should
 * not be left holding.
 */
internal fun forgetWriteProbe(context: Context, prefsName: String) {
    KeystoreEncryptedPrefs.create(context, prefsName).edit().remove(ANCHOR_KEY).commit()
}

/**
 * The stored name the deterministic fallback epoch gives [plainKey].
 *
 * Mirrors the store's own derivation rather than calling it, which is the point:
 * every input is a constant in the APK plus the file name, so a test derives it
 * exactly as anything able to write the directory would.
 */
internal fun fallbackNameIn(prefsName: String, plainKey: String): String = hmacName(
    MessageDigest.getInstance("SHA-256")
        .digest("$DETERMINISTIC_HMAC_SEED:$prefsName".toByteArray(Charsets.UTF_8)),
    plainKey
)

/** The derivation key a build in the v0.6.0 window persisted: the seed alone, no file name. */
internal fun publishedGlobalKey(): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(DETERMINISTIC_HMAC_SEED.toByteArray(Charsets.UTF_8))

/** The stored name [plainKey] takes in a file still carrying [publishedGlobalKey]. */
internal fun globalEpochNameOf(plainKey: String): String = hmacName(publishedGlobalKey(), plainKey)

private fun hmacName(key: ByteArray, plainKey: String): String {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return Base64.encodeToString(
        mac.doFinal(plainKey.toByteArray(Charsets.UTF_8)),
        Base64.NO_WRAP or Base64.URL_SAFE
    )
}

private const val ANCHOR_KEY = "__test_anchor__"
private const val DETERMINISTIC_HMAC_SEED = "keystore_prefs_hmac_key"

/** The one entry the store keeps under its literal name. */
internal const val HMAC_KEY_PREF = "__hmac_key__"

/** The store's own index, under the name the fallback epoch gives it. */
internal const val KEY_REGISTRY = "__keys__"

/** The marker KeystoreEncryptedPrefs puts on a value bound to its key name. */
internal const val BOUND_PREFIX = "v2:"
