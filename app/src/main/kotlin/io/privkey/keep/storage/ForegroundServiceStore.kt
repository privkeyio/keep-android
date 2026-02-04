package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences

class ForegroundServiceStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_foreground_service"
        private const val KEY_ENABLED = "foreground_service_enabled"
    }

    private val prefs: SharedPreferences = run {
        val newPrefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        LegacyPrefsMigration.migrateIfNeeded(context, PREFS_NAME, newPrefs)
    }

    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false)

    fun setEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENABLED, enabled).commit()
    }
}
