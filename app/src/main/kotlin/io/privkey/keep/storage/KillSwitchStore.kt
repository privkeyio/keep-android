package io.privkey.keep.storage

import android.content.Context

class KillSwitchStore(private val context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_kill_switch"
        private const val KEY_ENABLED = "kill_switch_enabled"
        private const val KEY_MIGRATED = "migrated_to_core"
    }

    private val prefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    fun hasMigrated(): Boolean = prefs.getBoolean(KEY_MIGRATED, false)

    fun legacyEnabled(): Boolean = LegacyPrefsMigration.migrateBooleanIfNeeded(
        context, PREFS_NAME, KEY_ENABLED, prefs, safeDefault = false
    )

    fun markMigrated() {
        prefs.edit().putBoolean(KEY_MIGRATED, true).remove(KEY_ENABLED).commit()
    }
}
