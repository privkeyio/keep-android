package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.annotation.StringRes
import io.privkey.keep.R

enum class SignPolicy(@StringRes val displayNameRes: Int, @StringRes val descriptionRes: Int) {
    MANUAL(R.string.sign_policy_manual, R.string.sign_policy_manual_description),
    BASIC(R.string.sign_policy_basic, R.string.sign_policy_basic_description),
    AUTO(R.string.sign_policy_auto, R.string.sign_policy_auto_description);

    companion object {
        fun fromOrdinal(ordinal: Int): SignPolicy = entries.getOrElse(ordinal) { MANUAL }
    }
}

class SignPolicyStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_sign_policy"
        private const val KEY_GLOBAL_POLICY = "global_sign_policy"
    }

    private val prefs: SharedPreferences = run {
        val newPrefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        LegacyPrefsMigration.migrateIfNeeded(context, PREFS_NAME, newPrefs)
    }

    fun getGlobalPolicy(): SignPolicy {
        val ordinal = prefs.getInt(KEY_GLOBAL_POLICY, SignPolicy.MANUAL.ordinal)
        return SignPolicy.fromOrdinal(ordinal)
    }

    fun setGlobalPolicy(policy: SignPolicy) {
        prefs.edit().putInt(KEY_GLOBAL_POLICY, policy.ordinal).commit()
    }
}
