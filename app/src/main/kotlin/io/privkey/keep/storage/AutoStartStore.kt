package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences

class AutoStartStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_auto_start"
        private const val KEY_ENABLED = "auto_start_enabled"
    }

    private val prefs: SharedPreferences = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false)

    fun setEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENABLED, enabled).commit()
    }
}
