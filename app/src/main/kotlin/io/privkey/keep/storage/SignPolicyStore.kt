package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.annotation.StringRes
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.privkey.keep.R

enum class SignPolicy(@StringRes val displayNameRes: Int, @StringRes val descriptionRes: Int) {
    BASIC(R.string.sign_policy_basic, R.string.sign_policy_basic_description),
    MANUAL(R.string.sign_policy_manual, R.string.sign_policy_manual_description);

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
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun getGlobalPolicy(): SignPolicy {
        val ordinal = prefs.getInt(KEY_GLOBAL_POLICY, SignPolicy.MANUAL.ordinal)
        return SignPolicy.fromOrdinal(ordinal)
    }

    fun setGlobalPolicy(policy: SignPolicy) {
        prefs.edit().putInt(KEY_GLOBAL_POLICY, policy.ordinal).commit()
    }
}
