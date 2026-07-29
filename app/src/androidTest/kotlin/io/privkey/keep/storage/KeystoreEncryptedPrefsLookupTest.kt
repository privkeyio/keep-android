package io.privkey.keep.storage

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Stored key names are hashed with a per-file derivation key. When that key
 * cannot be persisted the store falls back to a deterministic one, and entries
 * written during that window stay hashed under it after the store recovers.
 *
 * A lookup that only probes the current derivation key misses those entries
 * entirely, and they read as if they had never been written. For the signer that
 * is not a lost preference: an unfindable rate-limiter counter presents as a
 * package with no recorded usage, which restarts its window and puts the hourly
 * and daily ceilings out of reach.
 *
 * These tests place an entry under the fallback derivation key and assert it is
 * still reachable, by relocating a normally-written entry so its ciphertext stays
 * valid and only the key name changes.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreEncryptedPrefsLookupTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before
    fun setup() = clear()

    @After
    fun teardown() = clear()

    // Block body on purpose: an expression body here returns the delete's Boolean,
    // which makes the @Before/@After methods non-void and JUnit refuses to
    // instantiate the class at all.
    private fun clear() {
        context.deleteSharedPreferences(PREFS_NAME)
    }

    private fun raw() = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Mirrors the store's fallback key derivation, so a test can name an entry the way that epoch would. */
    private fun fallbackHash(plainKey: String): String {
        val key = MessageDigest.getInstance("SHA-256")
            .digest("$DETERMINISTIC_SEED:$PREFS_NAME".toByteArray(Charsets.UTF_8))
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return Base64.encodeToString(
            mac.doFinal(plainKey.toByteArray(Charsets.UTF_8)),
            Base64.NO_WRAP or Base64.URL_SAFE
        )
    }

    /**
     * Writes [plainKey] normally, then moves its stored entry to the name the
     * fallback epoch would have used. The value is left untouched, so it stays
     * decryptable; only its location changes.
     */
    private fun writeUnderFallbackEpoch(plainKey: String, value: String) {
        val prefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        prefs.edit().putString("anchor", "0").commit()
        val before = raw().all.keys.toSet()
        prefs.edit().putString(plainKey, value).commit()
        val added = raw().all.keys.toSet() - before
        assertEquals("expected exactly one new stored entry", 1, added.size)

        val storedName = added.first()
        val storedValue = raw().getString(storedName, null)
        assertTrue("stored entry should have a value", storedValue != null)
        raw().edit().remove(storedName).putString(fallbackHash(plainKey), storedValue).commit()
    }

    @Test
    fun anEntryLeftUnderTheFallbackEpochIsStillReadable() {
        writeUnderFallbackEpoch("counter", "hourly=7")

        val reopened = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        assertEquals("hourly=7", reopened.getString("counter", null))
    }

    @Test
    fun anEntryLeftUnderTheFallbackEpochIsReportedAsPresent() {
        writeUnderFallbackEpoch("counter", "hourly=7")

        // `contains` is what separates "never written" from "written but not
        // readable" for the signer's storage backends, so it has to see it too.
        assertTrue(KeystoreEncryptedPrefs.create(context, PREFS_NAME).contains("counter"))
    }

    @Test
    fun anEntryLeftUnderTheFallbackEpochCanBeDeleted() {
        writeUnderFallbackEpoch("counter", "hourly=7")

        val prefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        assertTrue(prefs.edit().remove("counter").commit())

        val reopened = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        assertNull("a deleted entry must not come back", reopened.getString("counter", null))
    }

    @Test
    fun anOverwrittenFallbackEntryDoesNotResurrectAfterDeletion() {
        // The dangerous shape: a stranded entry, then a write from a fresh
        // instance, then a delete. If the stranded copy were merely remembered
        // rather than moved, the write would land under the current name, the
        // delete would remove only that one, and this read would hand back the
        // superseded value. For a policy selection that is a setting the user
        // replaced coming back, possibly the looser one.
        writeUnderFallbackEpoch("counter", "hourly=7")

        KeystoreEncryptedPrefs.create(context, PREFS_NAME)
            .edit().putString("counter", "hourly=99").commit()

        assertTrue(
            KeystoreEncryptedPrefs.create(context, PREFS_NAME)
                .edit().remove("counter").commit()
        )

        assertNull(
            "a superseded value must not survive the delete",
            KeystoreEncryptedPrefs.create(context, PREFS_NAME).getString("counter", null)
        )
    }

    @Test
    fun aFallbackEntryIsConsolidatedSoOnlyOneCopyRemains() {
        writeUnderFallbackEpoch("counter", "hourly=7")

        // Reading it moves it to the current name; the old location must not
        // linger, or a later write and delete would leave it behind.
        val before = raw().all.keys.size
        assertEquals("hourly=7", KeystoreEncryptedPrefs.create(context, PREFS_NAME).getString("counter", null))
        assertEquals("the entry should move, not duplicate", before, raw().all.keys.size)
    }

    @Test
    fun aKeyThatWasNeverWrittenIsStillAbsent() {
        KeystoreEncryptedPrefs.create(context, PREFS_NAME)
            .edit().putString("anchor", "0").commit()

        val prefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        assertNull(prefs.getString("never-written", null))
        assertTrue(!prefs.contains("never-written"))
    }

    companion object {
        private const val PREFS_NAME = "keystore_prefs_lookup_test"
        private const val DETERMINISTIC_SEED = "keystore_prefs_hmac_key"
    }
}
