package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import io.privkey.keep.BuildConfig
import io.privkey.keep.uniffi.SignPolicySelectionStorage
import java.security.MessageDigest

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

    // Both writes return the platform's own durable-write result. Reporting
    // whether the call threw would say nothing, since a commit can return false
    // without raising, and the core treats an unconfirmed write as indeterminate
    // rather than assuming the previous value survived.
    override fun save(key: String, value: String): Boolean =
        runCatching { prefs.edit().putString(key, value).commit() }
            .getOrElse {
                warn("save failed for $key", it)
                false
            }

    override fun remove(key: String): Boolean =
        runCatching { prefs.edit().remove(key).commit() }
            .getOrElse {
                warn("remove failed for $key", it)
                false
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
        // Same one-shot reasoning as MIGRATION_MARKER, for the per-app override copy
        // that AppSignPolicyOverrides.migrateLegacyOverrides performs.
        internal const val APP_OVERRIDE_MIGRATION_MARKER = "keep_sign_policy_app_overrides_migrated"
        const val GLOBAL_POLICY_KEY = "global_sign_policy"

        // Deliberately not derived from APP_OVERRIDE_MIGRATION_MARKER. Every key with this
        // prefix is swept from the marker file once the run-wide marker lands, and that
        // file is shared with LegacyPrefsMigration, whose keys are built from a prefs file
        // name. A prefix spelled out here cannot be produced by that scheme by accident.
        internal const val APP_OVERRIDE_MARKER_PREFIX = "keep_app_override_pkg_"

        /**
         * Marker key recording that the per-app copy was attempted for one package.
         *
         * These markers have to live in plain prefs rather than the encrypted file: a
         * marker that could fail to decrypt would read as absent, which is exactly the
         * absence-versus-unreadable ambiguity the marker exists to remove. So the key
         * cannot be the keyed hash the encrypted file uses for its own key names, whose
         * HMAC key only exists once something has been decrypted.
         *
         * The digest is obfuscation, not confidentiality, and nothing should be built on
         * it: it is unsalted over a namespace anyone who can read the data directory can
         * also enumerate, so recovering a name is a dictionary lookup, and the number of
         * markers shows how many apps are pinned. It is here because the rest of this
         * app does not spell caller package names into storage, and because a stable
         * digest is all a marker needs.
         *
         * The markers are swept once the run-wide marker lands, which is the ordinary
         * case. An install holding an expired override row that the sweep could not clear
         * never completes a run, so it keeps its markers until that row goes, and the
         * digest is the only thing covering them in the meantime.
         */
        internal fun appOverrideMarkerKey(callerPackage: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(callerPackage.toByteArray(Charsets.UTF_8))
            val suffix = Base64.encodeToString(
                digest,
                Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING
            )
            return APP_OVERRIDE_MARKER_PREFIX + suffix
        }

        /**
         * Stages the removal of every per-package override marker in [markers].
         *
         * Shared because two places need the same rule and for different
         * reasons: the migration drops them as it sets the run-wide marker, in
         * that one editor, and the account-switch wipe drops whatever an
         * incomplete run left behind. Takes the editor rather than committing,
         * so the first of those stays one commit.
         *
         * Only the per-package keys. What the run-wide markers should hold is
         * each caller's business: the migration sets its own as it sweeps, and
         * the account-switch wipe sets it too, so that no surviving row's tier
         * can be copied forward afterwards. Neither clears one, because a
         * cleared run-wide marker reopens a legacy copy for the next account.
         *
         * Filters the committed state rather than the editor's pending writes,
         * so a caller that stages a marker and then calls this in the same
         * editor keeps the one it staged. Neither caller does that, and a third
         * that wants to should commit first.
         */
        internal fun removeAppOverrideMarkers(
            markers: SharedPreferences,
            edit: SharedPreferences.Editor,
        ) {
            markers.all.keys
                .filter { it.startsWith(APP_OVERRIDE_MARKER_PREFIX) }
                .forEach { edit.remove(it) }
        }
    }
}
