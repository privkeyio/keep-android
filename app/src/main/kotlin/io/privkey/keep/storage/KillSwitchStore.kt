package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences

class KillSwitchStore(private val context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_kill_switch"
        private const val KEY_ENABLED = "kill_switch_enabled"
    }

    private val prefs: SharedPreferences = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    fun isEnabled(): Boolean {
        return LegacyPrefsMigration.migrateBooleanIfNeeded(
            context, PREFS_NAME, KEY_ENABLED, prefs, safeDefault = false
        )
    }

    fun setEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENABLED, enabled).commit()
    }
}
