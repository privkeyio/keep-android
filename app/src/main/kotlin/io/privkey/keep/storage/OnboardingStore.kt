package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences

// Presentation-only flag: records whether the first-run guidance has been shown
// so it appears once. Encodes no signing/authorization policy.
class OnboardingStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_onboarding"
        private const val KEY_COMPLETED = "onboarding_completed"
    }

    private val prefs: SharedPreferences = run {
        val newPrefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        LegacyPrefsMigration.migrateIfNeeded(context, PREFS_NAME, newPrefs)
    }

    fun isCompleted(): Boolean = prefs.getBoolean(KEY_COMPLETED, false)

    fun setCompleted(completed: Boolean) {
        prefs.edit().putBoolean(KEY_COMPLETED, completed).commit()
    }
}
