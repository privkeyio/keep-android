@file:Suppress("DEPRECATION")

package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.privkey.keep.BuildConfig

object LegacyPrefsMigration {

    private const val MIGRATION_MARKER_SUFFIX = "_migrated_v1"

    fun migrateIfNeeded(
        context: Context,
        prefsName: String,
        newPrefs: ReadablePrefs
    ): ReadablePrefs {
        val migrationMarker = prefsName + MIGRATION_MARKER_SUFFIX
        val markerPrefs = context.getSharedPreferences("keep_migration_markers", Context.MODE_PRIVATE)

        if (markerPrefs.getBoolean(migrationMarker, false)) {
            return newPrefs
        }

        try {
            val legacyPrefs = openLegacyPrefs(context, prefsName) ?: run {
                markerPrefs.edit().putBoolean(migrationMarker, true).apply()
                return newPrefs
            }

            val legacyData = legacyPrefs.all
            if (legacyData.isEmpty()) {
                markerPrefs.edit().putBoolean(migrationMarker, true).apply()
                return newPrefs
            }

            val editor = newPrefs.edit()
            for ((key, value) in legacyData) {
                when (value) {
                    is String -> editor.putString(key, value)
                    is Int -> editor.putInt(key, value)
                    is Long -> editor.putLong(key, value)
                    is Float -> editor.putFloat(key, value)
                    is Boolean -> editor.putBoolean(key, value)
                    is Set<*> -> {
                        @Suppress("UNCHECKED_CAST")
                        editor.putStringSet(key, value as Set<String>)
                    }
                }
            }

            if (editor.commit()) {
                markerPrefs.edit().putBoolean(migrationMarker, true).apply()
            }
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.w("LegacyPrefsMigration", "Migration failed for $prefsName", e)
            markerPrefs.edit().putBoolean(migrationMarker, true).apply()
        }

        return newPrefs
    }

    fun migrateStringIfNeeded(
        context: Context,
        prefsName: String,
        key: String,
        newPrefs: SharedPreferences
    ): String? {
        val existing = newPrefs.getString(key, null)
        if (existing != null) return existing

        val migrationMarker = "${prefsName}_${key}_migrated"
        val markerPrefs = context.getSharedPreferences("keep_migration_markers", Context.MODE_PRIVATE)
        if (markerPrefs.getBoolean(migrationMarker, false)) return null

        try {
            val legacyPrefs = openLegacyPrefs(context, prefsName)
            val legacyValue = legacyPrefs?.getString(key, null)

            if (legacyValue != null) {
                if (newPrefs.edit().putString(key, legacyValue).commit()) {
                    markerPrefs.edit().putBoolean(migrationMarker, true).apply()
                    return legacyValue
                }
            } else {
                markerPrefs.edit().putBoolean(migrationMarker, true).apply()
            }
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.w("LegacyPrefsMigration", "Migration failed for $prefsName", e)
            markerPrefs.edit().putBoolean(migrationMarker, true).apply()
        }

        return null
    }

    /**
     * Reads [key] for a caller that carries legacy state forward, reporting the
     * three answers apart rather than collapsing them to a default.
     *
     * A value that cannot be read is the case this exists to separate. Collapsing
     * it to a default says the value was confirmed when it was not, and a caller
     * that acts on that confirmation resumes on a restriction it never saw.
     *
     * Both copies are consulted, because they fail independently: [newPrefs] and
     * the legacy store share one underlying file but name their entries
     * differently and encrypt under different keys, and nothing ever deletes the
     * legacy entry. So a value the new store cannot decrypt, or cannot find
     * because the file's name key was replaced, is still answerable from the
     * legacy copy. [PrefRead.Absent] is returned only when neither copy holds
     * anything, and [PrefRead.Unreadable] whenever an answer was owed and could
     * not be had.
     *
     * A pure read: nothing is written, nothing is marked, and no state carries
     * between calls. The caller's own record of having carried the value is what
     * stops this running twice, and unlike a marker file it is authenticated.
     */
    fun readBooleanForMigration(
        context: Context,
        prefsName: String,
        key: String,
        newPrefs: ReadablePrefs,
    ): PrefRead<Boolean> {
        val fromNewStore = newPrefs.readBoolean(key)
        if (fromNewStore is PrefRead.Found) return fromNewStore

        // Null means the legacy store could not be opened at all, so this is a
        // read that was owed an answer and did not get one.
        val legacyPrefs = openLegacyPrefs(context, prefsName) ?: return PrefRead.Unreadable

        // The legacy read fails in two directions and neither may reach the caller
        // as a confirmed value. A value that will not decrypt raises, and letting
        // that escape is worse here than a wrong answer: it lands in the carry's
        // outer handler, which engages the switch without retiring the carry, so
        // the carry re-applies itself on every launch and re-engages after the
        // user has deliberately cleared it. A value that decrypts to some other
        // type does not raise at all; this API answers with the caller's default,
        // which is the exact conflation this function exists to remove. Reading
        // under both defaults separates them: a stored boolean ignores the
        // default, so two different answers mean the value is not a boolean.
        val fromLegacy: PrefRead<Boolean>? = runCatching {
            if (legacyPrefs.contains(key)) {
                val asFalse = legacyPrefs.getBoolean(key, false)
                if (asFalse == legacyPrefs.getBoolean(key, true)) {
                    PrefRead.Found(asFalse)
                } else {
                    PrefRead.Unreadable
                }
            } else {
                null
            }
        }.getOrElse { PrefRead.Unreadable }
        if (fromLegacy != null) return fromLegacy

        // The legacy store has nothing. If the new store held something it could
        // not read, that is still the state of the setting, and no absence has
        // been established.
        return if (fromNewStore == PrefRead.Unreadable) PrefRead.Unreadable else PrefRead.Absent
    }

    private fun openLegacyPrefs(context: Context, prefsName: String): SharedPreferences? {
        return try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                context,
                prefsName,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.w("LegacyPrefsMigration", "Failed to open legacy prefs: $prefsName", e)
            null
        }
    }
}
