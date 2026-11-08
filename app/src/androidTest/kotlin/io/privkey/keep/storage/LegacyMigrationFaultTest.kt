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
        markers().edit().remove(STRING_MARKER).remove(STORE_MARKER).commit()
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
        assertEquals(
            "legacy-secret",
            LegacyPrefsMigration.migrateStringIfNeeded(context, TEST_PREFS, KEY, newStore())
        )
        assertEquals("legacy-secret", newStore().getString(KEY, null))
    }

    @Test
    fun aStringAbsentFromAnOpenLegacyStoreIsMarked() {
        assertTrue(legacyStore().edit().putString("other", "x").commit())

        assertNull(LegacyPrefsMigration.migrateStringIfNeeded(context, TEST_PREFS, KEY, newStore()))
        assertTrue(markers().getBoolean(STRING_MARKER, false))
    }

    @Test
    fun aStoreTheLegacyCopyCouldNotOpenIsCarriedOnceItCan() {
        assertTrue(legacyStore().edit().putString(KEY, "legacy-value").putInt("count", 3).commit())

        whileLegacyWillNotOpen { LegacyPrefsMigration.migrateIfNeeded(context, TEST_PREFS, newStore()) }

        assertEquals("a fault must not mark the store as carried", false, markers().getBoolean(STORE_MARKER, false))
        LegacyPrefsMigration.migrateIfNeeded(context, TEST_PREFS, newStore())
        assertEquals("legacy-value", newStore().getString(KEY, null))
        assertEquals(3, newStore().getInt("count", 0))
        assertTrue(markers().getBoolean(STORE_MARKER, false))
    }

    private companion object {
        const val TEST_PREFS = "test_legacy_migration_fault"
        const val KEY = "secret"
        const val STRING_MARKER = "${TEST_PREFS}_${KEY}_migrated"
        const val STORE_MARKER = "${TEST_PREFS}_migrated_v1"
        val KEYSETS = listOf(
            "__androidx_security_crypto_encrypted_prefs_key_keyset__",
            "__androidx_security_crypto_encrypted_prefs_value_keyset__",
        )
    }
}
