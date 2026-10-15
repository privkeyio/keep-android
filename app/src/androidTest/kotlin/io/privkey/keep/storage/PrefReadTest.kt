package io.privkey.keep.storage

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * The typed getters answer with the caller's default whether a value was never stored or
 * is stored and will not decrypt, so a store holding real values reports itself as empty.
 * [ReadablePrefs] reports which of the two it saw.
 *
 * Two faults have to arrive as the same answer here, because they do not through the
 * getters: a value that will not decrypt, which a getter resolves to the default, and a
 * name that will not resolve, which a getter raises on, since name resolution goes
 * through the file's HMAC key and that decrypt is unguarded. These stage both, and assert
 * the getters still behave exactly as they did for every caller whose default is correct.
 */
@RunWith(AndroidJUnit4::class)
class PrefReadTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before fun setup() = clear()
    @After fun teardown() = clear()

    private fun clear() {
        context.deleteSharedPreferences(PREFS_NAME)
    }

    private fun raw() = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private fun open() = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    /** The stored name a write lands on, identified by what the write adds. */
    private fun writeAndFindStoredName(write: (ReadablePrefs) -> Unit): String {
        open().edit().putString("anchor", "0").commit()
        val before = raw().all.keys.toSet()
        write(open())
        val added = raw().all.keys.toSet() - before
        assertEquals("expected exactly one new stored entry", 1, added.size)
        return added.first()
    }

    /**
     * Breaks one value the way a lost Keystore alias breaks every value: the last byte of
     * the ciphertext is flipped, so the IV and body stay well formed and the failure is
     * the GCM tag check rather than a length or decode error on a different branch.
     */
    private fun corruptStoredValue(storedName: String) {
        val stored = raw().getString(storedName, null)!!
        assertTrue(
            "this flips a byte of the body, so the value has to carry the marker it is written with",
            stored.startsWith(BOUND_PREFIX)
        )
        val bytes = Base64.decode(stored.removePrefix(BOUND_PREFIX), Base64.NO_WRAP)
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
        raw().edit()
            .putString(storedName, BOUND_PREFIX + Base64.encodeToString(bytes, Base64.NO_WRAP))
            .commit()
    }

    /**
     * A value written the way values were before they were bound to their key name, so it
     * decrypts without the AAD step and its plaintext is whatever is passed here. The only
     * way to stage a body that decrypts and then will not parse.
     */
    private fun unboundCiphertext(plaintext: String): String {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = keyStore.getKey("keep_prefs_$PREFS_NAME", null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
        return Base64.encodeToString(
            cipher.iv + cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8)),
            Base64.NO_WRAP
        )
    }

    /**
     * Breaks name resolution for the whole file the way losing the Keystore alias breaks
     * it: the stored HMAC key no longer decrypts, so every lookup raises.
     */
    private fun breakNameResolution() {
        val stored = raw().getString(HMAC_KEY, null)!!
        val bytes = Base64.decode(stored.removePrefix(BOUND_PREFIX), Base64.NO_WRAP)
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
        val corrupted = Base64.encodeToString(bytes, Base64.NO_WRAP)
        raw().edit()
            .putString(HMAC_KEY, if (stored.startsWith(BOUND_PREFIX)) BOUND_PREFIX + corrupted else corrupted)
            .commit()
    }

    @Test
    fun a_stored_value_reads_as_found() {
        open().edit().putString("k", "v").commit()

        assertEquals(PrefRead.Found("v"), open().readString("k"))
    }

    @Test
    fun every_typed_read_round_trips() {
        open().edit()
            .putInt("i", 7)
            .putLong("l", 8L)
            .putBoolean("b", true)
            .putStringSet("s", mutableSetOf("one", "two"))
            .commit()

        val prefs = open()
        assertEquals(PrefRead.Found(7), prefs.readInt("i"))
        assertEquals(PrefRead.Found(8L), prefs.readLong("l"))
        assertEquals(PrefRead.Found(true), prefs.readBoolean("b"))
        assertEquals(PrefRead.Found(setOf("one", "two")), prefs.readStringSet("s"))
    }

    @Test
    fun an_empty_set_round_trips_as_an_empty_set() {
        // It stores as the bare type prefix with no body, which is the one value whose
        // parse has nothing to split.
        open().edit().putStringSet("s", mutableSetOf()).commit()

        assertEquals(PrefRead.Found(emptySet<String>()), open().readStringSet("s"))
    }

    @Test
    fun a_name_that_was_never_written_reads_as_absent() {
        open().edit().putString("other", "v").commit()

        val prefs = open()
        assertEquals(PrefRead.Absent, prefs.readString("k"))
        assertEquals(PrefRead.Absent, prefs.readStringSet("k"))
        assertEquals(PrefRead.Absent, prefs.readInt("k"))
        assertEquals(PrefRead.Absent, prefs.readLong("k"))
        assertEquals(PrefRead.Absent, prefs.readBoolean("k"))
    }

    @Test
    fun a_value_that_will_not_decrypt_reads_as_unreadable() {
        // The distinction this whole type exists for: the value is on disk and intact as
        // a record, so reporting it absent would invite a caller to write over it.
        corruptStoredValue(writeAndFindStoredName { it.edit().putString("k", "v").commit() })

        assertEquals(PrefRead.Unreadable, open().readString("k"))
    }

    @Test
    fun a_value_holding_another_type_reads_as_unreadable() {
        // Folded in with a failed decrypt on purpose: it is deterministically wrong, so
        // no retry changes it, and no caller has a reason to treat it differently.
        open().edit().putInt("k", 7).commit()

        assertEquals(PrefRead.Unreadable, open().readString("k"))
    }

    @Test
    fun a_body_that_will_not_parse_reads_as_unreadable_rather_than_absent() {
        // Needs a crafted value: a body reaches the parse only behind a matching type
        // prefix, so anything written through the API fails the prefix check first and
        // never exercises the parse at all.
        val storedName = writeAndFindStoredName { it.edit().putInt("k", 7).commit() }
        raw().edit().putString(storedName, unboundCiphertext("i:not-a-number")).commit()

        assertEquals(PrefRead.Unreadable, open().readInt("k"))
    }

    @Test
    fun a_name_that_will_not_resolve_reads_as_unreadable_rather_than_raising() {
        // What makes the type total. This fault is the one a lost Keystore alias produces,
        // and it comes out of the getters as an exception rather than as a default, so a
        // caller choosing what to do about an unreadable value would otherwise have to
        // handle both an answer and a throw.
        open().edit().putString("k", "v").commit()
        breakNameResolution()

        val prefs = open()
        assertEquals(PrefRead.Unreadable, prefs.readString("k"))
        assertEquals(PrefRead.Unreadable, prefs.readBoolean("k"))
        assertThrows(Exception::class.java) { prefs.getString("k", null) }
    }

    @Test
    fun the_ordinary_getters_still_answer_the_default_for_an_unreadable_value() {
        // No caller changes behavior by this commit: every existing getter resolves all
        // three cases to the default exactly as it did before.
        corruptStoredValue(writeAndFindStoredName { it.edit().putString("k", "v").commit() })

        val prefs = open()
        assertTrue("the premise of Unreadable: the name is still indexed", prefs.contains("k"))
        assertNull(prefs.getString("k", null))
        assertEquals("fallback", prefs.getString("k", "fallback"))
        assertEquals(PrefRead.Unreadable, prefs.readString("k"))
    }

    private companion object {
        const val PREFS_NAME = "pref_read_test"
        const val HMAC_KEY = "__hmac_key__"
        // The marker KeystoreEncryptedPrefs puts on a value bound to its key name.
        const val BOUND_PREFIX = "v2:"
    }
}
