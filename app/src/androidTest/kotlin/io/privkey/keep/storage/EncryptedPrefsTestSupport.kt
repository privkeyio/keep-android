package io.privkey.keep.storage

import android.content.Context
import android.util.Base64
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
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
 * Breaks the stored value of [plainKey], which must already be written.
 *
 * [writeAndFindStoredName] finds a name by what a write adds, which does not work for a
 * key already present. Here the name is found the only other way available from outside:
 * removing the key and seeing which entry goes. [restore] then writes it back, which lands
 * on the same name because the file's HMAC key is unchanged, and that value is broken.
 */
internal fun corruptExistingValue(
    context: Context,
    prefsName: String,
    plainKey: String,
    restore: (android.content.SharedPreferences.Editor) -> Unit
) {
    val before = rawPrefs(context, prefsName).all.keys.toSet()
    KeystoreEncryptedPrefs.create(context, prefsName).edit().remove(plainKey).commit()
    val removed = before - rawPrefs(context, prefsName).all.keys.toSet()
    assertEquals("expected exactly one entry to go with $plainKey: $removed", 1, removed.size)
    val editor = KeystoreEncryptedPrefs.create(context, prefsName).edit()
    restore(editor)
    editor.commit()
    corruptStoredValue(context, prefsName, removed.single())
}

/**
 * Breaks name resolution for a whole file, the other half of the fault a lost Keystore
 * alias produces.
 *
 * [corruptStoredValue] breaks one value; this breaks the file's own HMAC key, which every
 * lookup in the file goes through. That decrypt is unguarded, so the failure raises rather
 * than resolving to a value, and reads survive it only because they are wrapped. The same
 * last-byte flip, for the same reason: the failure stays the GCM tag check.
 */
internal fun breakNameResolution(context: Context, prefsName: String) {
    val raw = rawPrefs(context, prefsName)
    val stored = raw.getString(HMAC_KEY_PREF, null)
    assertNotNull("the file must already hold an HMAC key to corrupt", stored)
    val bytes = Base64.decode(stored!!.removePrefix(BOUND_PREFIX), Base64.NO_WRAP)
    bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
    val corrupted = Base64.encodeToString(bytes, Base64.NO_WRAP)
    raw.edit()
        .putString(
            HMAC_KEY_PREF,
            if (stored.startsWith(BOUND_PREFIX)) BOUND_PREFIX + corrupted else corrupted
        )
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

/**
 * The whitelist as a plain list, for tests whose subject is not the read.
 *
 * Raises on a fault rather than answering an empty list, so a test that stages
 * one by accident fails instead of quietly asserting against the collapse this
 * store no longer performs.
 */
internal fun RelayAuthWhitelistStore.hosts(): List<String> = when (val read = readHosts()) {
    is PrefRead.Found -> read.value
    PrefRead.Absent, PrefRead.Unreadable -> error("the whitelist read answered $read")
}

private const val ANCHOR_KEY = "__test_anchor__"
private const val DETERMINISTIC_HMAC_SEED = "keystore_prefs_hmac_key"

/** The one entry the store keeps under its literal name. */
internal const val HMAC_KEY_PREF = "__hmac_key__"

/** The store's own index, under the name the fallback epoch gives it. */
internal const val KEY_REGISTRY = "__keys__"

/** The marker KeystoreEncryptedPrefs puts on a value bound to its key name. */
internal const val BOUND_PREFIX = "v2:"
