package io.privkey.keep.nip55

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.StorageRead
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidSigningRateLimiterStorageTest {

    private lateinit var context: Context
    private lateinit var storage: AndroidSigningRateLimiterStorage

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        storage = AndroidSigningRateLimiterStorage(context)
        storage.clear()
    }

    @After
    fun teardown() {
        storage.clear()
    }

    @Test
    fun saveThenLoadReturnsStoredValue() {
        storage.save("com.example.app", "counter=3;cooloff=0")
        assertEquals(StorageRead.Found("counter=3;cooloff=0"), storage.load("com.example.app"))
    }

    @Test
    fun saveOverwritesExistingValue() {
        storage.save("com.example.app", "counter=3")
        storage.save("com.example.app", "counter=4")
        assertEquals(StorageRead.Found("counter=4"), storage.load("com.example.app"))
    }

    @Test
    fun distinctKeysRoundTripIndependently() {
        storage.save("com.example.a", "counter=1")
        storage.save("com.example.b", "counter=2")

        assertEquals(StorageRead.Found("counter=1"), storage.load("com.example.a"))
        assertEquals(StorageRead.Found("counter=2"), storage.load("com.example.b"))
    }

    @Test
    fun loadOfAbsentKeyReturnsNull() {
        assertEquals(StorageRead.Absent, storage.load("com.example.missing"))
    }

    @Test
    fun removeThenLoadReturnsNull() {
        storage.save("com.example.app", "counter=1")
        storage.remove("com.example.app")
        assertEquals(StorageRead.Absent, storage.load("com.example.app"))
    }

    @Test
    fun removeLeavesOtherKeysIntact() {
        storage.save("com.example.a", "counter=1")
        storage.save("com.example.b", "counter=2")

        storage.remove("com.example.a")

        assertEquals(StorageRead.Absent, storage.load("com.example.a"))
        assertEquals(StorageRead.Found("counter=2"), storage.load("com.example.b"))
    }

    @Test
    fun removeOfAbsentKeyIsNoOp() {
        storage.save("com.example.a", "counter=1")
        storage.remove("com.example.missing")
        assertEquals(StorageRead.Found("counter=1"), storage.load("com.example.a"))
    }

    @Test
    fun clearWipesAllEntries() {
        storage.save("com.example.a", "counter=1")
        storage.save("com.example.b", "counter=2")
        assertEquals(StorageRead.Found("counter=1"), storage.load("com.example.a"))
        assertEquals(StorageRead.Found("counter=2"), storage.load("com.example.b"))

        storage.clear()

        assertEquals(StorageRead.Absent, storage.load("com.example.a"))
        assertEquals(StorageRead.Absent, storage.load("com.example.b"))
    }

    @Test
    fun savedValueSurvivesFreshAdapterInstance() {
        storage.save("com.example.app", "counter=7")

        val reopened = AndroidSigningRateLimiterStorage(context)
        assertEquals(StorageRead.Found("counter=7"), reopened.load("com.example.app"))
    }

    @Test
    fun storedEntriesAreEncryptedAtRest() {
        storage.save("com.example.app", "counter=3;cooloff=0")

        val basePrefs = context.getSharedPreferences("nip55_rate_limiter", Context.MODE_PRIVATE)
        assertTrue(
            "backing prefs must receive encrypted entries; empty means prefs-name drift or a no-write regression",
            basePrefs.all.isNotEmpty()
        )
        for ((key, value) in basePrefs.all) {
            assertFalse(key.contains("com.example.app"))
            assertFalse(value.toString().contains("com.example.app"))
            assertFalse(value.toString().contains("counter=3;cooloff=0"))
            assertFalse(value.toString().contains("counter=3"))
        }
    }

    @Test
    fun emptyValueRoundTripsAsEmptyNotNull() {
        storage.save("com.example.app", "")
        assertEquals(StorageRead.Found(""), storage.load("com.example.app"))
    }

    @Test
    fun clearPersistsAcrossInstances() {
        storage.save("com.example.app", "counter=1")
        storage.clear()

        val reopened = AndroidSigningRateLimiterStorage(context)
        assertEquals(StorageRead.Absent, reopened.load("com.example.app"))
    }

    // The three-state read is the point of this backend. Absent means "no usage
    // yet" and lets the core start a fresh window; Unavailable means "unknown"
    // and makes it refuse. Conflating them is what removes the rate ceiling.

    @Test
    fun aPresentButUndecryptableEntryReadsUnavailableNotAbsent() {
        storage.save("com.example.app", "counter=1")

        // Corrupt the stored ciphertext in place, leaving the key itself intact,
        // so the entry is still present but can no longer be decrypted. Reporting
        // Absent here would restart the package's window on every request.
        val raw = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val encryptedKey = raw.all.keys.firstOrNull { it != KEY_REGISTRY && it != HMAC_KEY }
        assertTrue("expected a stored entry to corrupt", encryptedKey != null)
        raw.edit().putString(encryptedKey, "not-valid-ciphertext").commit()

        assertEquals(
            StorageRead.Unavailable,
            AndroidSigningRateLimiterStorage(context).load("com.example.app")
        )
    }

    @Test
    fun aNeverWrittenKeyReadsAbsentSoTheWindowCanStartFresh() {
        assertEquals(StorageRead.Absent, storage.load("com.example.never.written"))
    }

    companion object {
        private const val PREFS_NAME = "nip55_rate_limiter"
        private const val KEY_REGISTRY = "__keys__"
        private const val HMAC_KEY = "__hmac_key__"
    }
}
