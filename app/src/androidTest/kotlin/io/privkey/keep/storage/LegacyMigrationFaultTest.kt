// The legacy store is staged through the same deprecated Jetpack API the
// migration opens it with, so the suppression matches LegacyPrefsMigration's.
@file:Suppress("DEPRECATION")

package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A legacy store that will not open is not an empty one. The fault is staged by
 * breaking the legacy store's own keysets in the file, which makes it fail to open
 * the way a transient Keystore fault does, and then putting them back.
 */
@RunWith(AndroidJUnit4::class)
class LegacyMigrationFaultTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before fun setup() = wipe()
    @After fun teardown() = wipe()

    private fun wipe() {
        context.deleteSharedPreferences(TEST_PREFS)
        markers().edit().remove(STRING_MARKER).commit()
    }

    private fun markers() = context.getSharedPreferences("keep_migration_markers", Context.MODE_PRIVATE)
    private fun raw() = context.getSharedPreferences(TEST_PREFS, Context.MODE_PRIVATE)
    private fun newStore() = KeystoreEncryptedPrefs.create(context, TEST_PREFS)

    private fun legacyStore(): SharedPreferences = EncryptedSharedPreferences.create(
        context,
        TEST_PREFS,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    /** Breaks the legacy keysets, runs [block], then restores them. */
    private fun <T> whileLegacyWillNotOpen(block: () -> T): T {
        val saved = KEYSETS.associateWith { raw().getString(it, null) }
        assertTrue("the legacy store must have keysets to break", saved.values.all { it != null })
        assertTrue(raw().edit().apply { KEYSETS.forEach { putString(it, "not-a-keyset") } }.commit())
        try {
            return block()
        } finally {
            assertTrue(raw().edit().apply { saved.forEach { (k, v) -> putString(k, v) } }.commit())
        }
    }

    @Test
    fun aStringTheLegacyStoreCouldNotOpenIsCarriedOnceItCan() {
        assertTrue(legacyStore().edit().putString(KEY, "legacy-secret").commit())

        val duringFault = whileLegacyWillNotOpen {
            LegacyPrefsMigration.migrateStringIfNeeded(context, TEST_PREFS, KEY, newStore())
        }

        assertNull(duringFault)
        assertEquals("a fault must not mark the value as carried", false, markers().getBoolean(STRING_MARKER, false))
        // As the faulted launch goes on, the new store is used, which writes its own key
        // material into the shared file. The retry reads one key and is not affected.
        newStore().getString("unrelated", null)
        assertEquals(
            "legacy-secret",
            LegacyPrefsMigration.migrateStringIfNeeded(context, TEST_PREFS, KEY, newStore())
        )
        assertEquals("legacy-secret", newStore().getString(KEY, null))
    }

    @Test
    fun aKeyMintedDuringAFaultIsNotReplacedByTheLegacyValue() {
        val legacyKey = android.util.Base64.encodeToString(ByteArray(32) { 1 }, android.util.Base64.NO_WRAP)
        assertTrue(legacyStore().edit().putString(KEY, legacyKey).commit())

        whileLegacyWillNotOpen {
            io.privkey.keep.nip55.Nip55Database.getOrCreateKey(context, KEY, prefsName = TEST_PREFS)
        }

        assertTrue(markers().getBoolean(STRING_MARKER, false))
        // The minted entry going missing is the case a later launch would otherwise
        // answer from the legacy copy.
        assertTrue(newStore().edit().remove(KEY).commit())
        assertNull(LegacyPrefsMigration.migrateStringIfNeeded(context, TEST_PREFS, KEY, newStore()))
        // Without the marker the legacy copy does answer, so the marker is what refused it.
        assertTrue(markers().edit().remove(STRING_MARKER).commit())
        assertEquals(legacyKey, LegacyPrefsMigration.migrateStringIfNeeded(context, TEST_PREFS, KEY, newStore()))
    }

    @Test
    fun aStringAbsentFromAnOpenLegacyStoreIsMarked() {
        assertTrue(legacyStore().edit().putString("other", "x").commit())

        assertNull(LegacyPrefsMigration.migrateStringIfNeeded(context, TEST_PREFS, KEY, newStore()))
        assertTrue(markers().getBoolean(STRING_MARKER, false))
    }

    private companion object {
        const val TEST_PREFS = "test_legacy_migration_fault"
        const val KEY = "secret"
        const val STRING_MARKER = "${TEST_PREFS}_${KEY}_migrated"
        val KEYSETS = listOf(
            "__androidx_security_crypto_encrypted_prefs_key_keyset__",
            "__androidx_security_crypto_encrypted_prefs_value_keyset__",
        )
    }
}
