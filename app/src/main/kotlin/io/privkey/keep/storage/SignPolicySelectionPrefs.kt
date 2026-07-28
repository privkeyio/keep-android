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
 * Int into "keep_sign_policy", and the core reads that key as a String, so sharing
 * the file would read the legacy value as absent and silently reset the user's
 * selection. The value is copied across once instead.
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
     * The legacy key is left in place, so this stays non-destructive.
     *
     * Gated on a persisted marker rather than on "is the new value absent". The
     * encrypted-prefs layer returns the default when a value cannot be decrypted, so
     * an unreadable store is indistinguishable from an unset one; gating on absence
     * would re-run this after any such failure and resurrect the legacy selection,
     * which may be LOOSER than what the user has chosen since. The marker is set
     * whether or not the copy succeeds, so this runs at most once: a failed copy
     * leaves the store unset, which the core resolves to `Manual`, the strictest
     * tier. Losing a selection that way costs the user a re-pick; resurrecting a
     * stale one would silently widen auto-approval.
     */
    private fun migrateLegacyGlobalPolicy(context: Context) {
        val markerPrefs = context.getSharedPreferences(MARKER_PREFS_NAME, Context.MODE_PRIVATE)
        if (markerPrefs.getBoolean(MIGRATION_MARKER, false)) return

        runCatching {
            if (prefs.getString(GLOBAL_POLICY_KEY, null) == null) {
                val legacyPrefs = LegacyPrefsMigration.migrateIfNeeded(
                    context,
                    LEGACY_PREFS_NAME,
                    KeystoreEncryptedPrefs.create(context, LEGACY_PREFS_NAME)
                )
                val ordinal = legacyPrefs.getInt(GLOBAL_POLICY_KEY, -1)
                SignPolicy.entries.getOrNull(ordinal)?.let { legacyPolicy ->
                    prefs.edit()
                        .putString(GLOBAL_POLICY_KEY, legacyPolicy.toSelection().ordinal.toString())
                        .commit()
                }
            }
        }.onFailure { warn("legacy global policy migration failed", it) }

        markerPrefs.edit().putBoolean(MIGRATION_MARKER, true).apply()
    }

    private fun warn(message: String, error: Throwable) {
        if (BuildConfig.DEBUG) Log.w(TAG, message, error)
    }

    companion object {
        private const val PREFS_NAME = "keep_sign_policy_selection"
        private const val LEGACY_PREFS_NAME = "keep_sign_policy"
        // Shared with LegacyPrefsMigration so all one-shot migration markers live
        // together; holds no secret, only a boolean "already attempted" flag.
        internal const val MARKER_PREFS_NAME = "keep_migration_markers"
        internal const val MIGRATION_MARKER = "keep_sign_policy_selection_migrated"
        const val GLOBAL_POLICY_KEY = "global_sign_policy"
    }
}
