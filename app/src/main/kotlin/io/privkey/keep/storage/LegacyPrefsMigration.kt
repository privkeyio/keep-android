package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

object LegacyPrefsMigration {

    private const val MIGRATION_MARKER_SUFFIX = "_migrated_v1"

    fun migrateIfNeeded(
        context: Context,
        prefsName: String,
        newPrefs: SharedPreferences
    ): SharedPreferences {
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
        } catch (_: Exception) {
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
        } catch (_: Exception) {
            markerPrefs.edit().putBoolean(migrationMarker, true).apply()
        }

        return null
    }

    fun migrateBooleanIfNeeded(
        context: Context,
        prefsName: String,
        key: String,
        newPrefs: SharedPreferences,
        safeDefault: Boolean
    ): Boolean {
        if (newPrefs.contains(key)) {
            return newPrefs.getBoolean(key, safeDefault)
        }

        val migrationMarker = "${prefsName}_${key}_migrated"
        val markerPrefs = context.getSharedPreferences("keep_migration_markers", Context.MODE_PRIVATE)
        if (markerPrefs.getBoolean(migrationMarker, false)) {
            return safeDefault
        }

        try {
            val legacyPrefs = openLegacyPrefs(context, prefsName)
            if (legacyPrefs != null && legacyPrefs.contains(key)) {
                val legacyValue = legacyPrefs.getBoolean(key, safeDefault)
                if (newPrefs.edit().putBoolean(key, legacyValue).commit()) {
                    markerPrefs.edit().putBoolean(migrationMarker, true).apply()
                    return legacyValue
                }
            } else {
                markerPrefs.edit().putBoolean(migrationMarker, true).apply()
            }
        } catch (_: Exception) {
            markerPrefs.edit().putBoolean(migrationMarker, true).apply()
        }

        return safeDefault
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
        } catch (_: Exception) {
            null
        }
    }
}
