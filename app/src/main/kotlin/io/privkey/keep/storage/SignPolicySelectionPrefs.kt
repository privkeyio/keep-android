package io.privkey.keep.storage

import android.content.Context
import android.util.Log
import io.privkey.keep.BuildConfig
import io.privkey.keep.uniffi.SignPolicySelectionStorage

private const val TAG = "SignPolicySelectionPrefs"

/**
 * Encrypted-prefs backend for the core-owned [io.privkey.keep.uniffi.SignPolicyStore].
 * The core owns the selection state and its precedence; Android only persists the
 * opaque key/value pairs.
 *
 * Every operation fails safe: a read error surfaces as "unset", which the core
 * resolves to `Manual`, the strictest tier. A storage fault must never propagate
 * into the signing path.
 *
 * Uses its own prefs file. The legacy Kotlin store wrote `global_sign_policy` as an
 * Int into "keep_sign_policy", and reading an Int key back as a String throws, so
 * the value is copied across once at construction instead of sharing the file.
 */
class SignPolicySelectionPrefs(context: Context) : SignPolicySelectionStorage {

    private val prefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    init {
        migrateLegacyGlobalPolicy(context)
    }

    override fun load(key: String): String? =
        runCatching { prefs.getString(key, null) }
            .onFailure { warn("load failed for $key", it) }
            .getOrNull()

    override fun save(key: String, value: String) {
        runCatching { prefs.edit().putString(key, value).commit() }
            .onFailure { warn("save failed for $key", it) }
    }

    override fun remove(key: String) {
        runCatching { prefs.edit().remove(key).commit() }
            .onFailure { warn("remove failed for $key", it) }
    }

    /**
     * One-time copy of the global selection the deleted Kotlin store wrote as an Int.
     * Idempotent: a value already in the new store is never overwritten, and the
     * legacy key is left in place so this stays non-destructive.
     */
    private fun migrateLegacyGlobalPolicy(context: Context) {
        runCatching {
            if (prefs.getString(GLOBAL_POLICY_KEY, null) != null) return@runCatching

            val legacyPrefs = LegacyPrefsMigration.migrateIfNeeded(
                context,
                LEGACY_PREFS_NAME,
                KeystoreEncryptedPrefs.create(context, LEGACY_PREFS_NAME)
            )
            val ordinal = legacyPrefs.getInt(GLOBAL_POLICY_KEY, -1)
            val legacyPolicy = SignPolicy.entries.getOrNull(ordinal) ?: return@runCatching

            prefs.edit()
                .putString(GLOBAL_POLICY_KEY, legacyPolicy.toSelection().ordinal.toString())
                .commit()
        }.onFailure { warn("legacy global policy migration failed", it) }
    }

    private fun warn(message: String, error: Throwable) {
        if (BuildConfig.DEBUG) Log.w(TAG, message, error)
    }

    companion object {
        private const val PREFS_NAME = "keep_sign_policy_selection"
        private const val LEGACY_PREFS_NAME = "keep_sign_policy"
        const val GLOBAL_POLICY_KEY = "global_sign_policy"
    }
}
