package io.privkey.keep.storage

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The typed getters answer with the caller's default whether a value was never stored or
 * is stored and will not decrypt, so a store whose Keystore alias is gone reports itself
 * as empty rather than as unreadable. [ReadablePrefs] reports which of the two it saw.
 *
 * These stage the second case the way the platform produces it, by corrupting a stored
 * value's ciphertext so its GCM tag check fails, and assert the ordinary getters still
 * behave exactly as before for every caller whose default is correct.
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
        val marked = stored.startsWith(BOUND_PREFIX)
        val bytes = Base64.decode(stored.removePrefix(BOUND_PREFIX), Base64.NO_WRAP)
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
        val corrupted = Base64.encodeToString(bytes, Base64.NO_WRAP)
        raw().edit()
            .putString(storedName, if (marked) BOUND_PREFIX + corrupted else corrupted)
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
    fun a_name_that_was_never_written_reads_as_absent() {
        open().edit().putString("other", "v").commit()

        assertEquals(PrefRead.Absent, open().readString("k"))
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
    fun a_value_that_will_not_parse_reads_as_unreadable_rather_than_absent() {
        // The parse runs inside the read, so a well-formed decrypt carrying a number this
        // type cannot hold is still the value being unusable, not the name being unused.
        open().edit().putString("k", "not-a-number").commit()
        assertEquals(PrefRead.Found("not-a-number"), open().readString("k"))

        assertEquals(PrefRead.Unreadable, open().readInt("k"))
    }

    @Test
    fun the_ordinary_getters_still_answer_the_default_for_an_unreadable_value() {
        // No caller changes behavior by this commit: every existing getter resolves all
        // three cases to the default exactly as it did before.
        corruptStoredValue(writeAndFindStoredName { it.edit().putString("k", "v").commit() })

        val prefs = open()
        assertNull(prefs.getString("k", null))
        assertEquals("fallback", prefs.getString("k", "fallback"))
        assertEquals(PrefRead.Unreadable, prefs.readString("k"))
    }

    private companion object {
        const val PREFS_NAME = "pref_read_test"
        // The marker KeystoreEncryptedPrefs puts on a value bound to its key name.
        const val BOUND_PREFIX = "v2:"
    }
}
