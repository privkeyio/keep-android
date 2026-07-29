package io.privkey.keep.nip55

import android.util.Log
import io.privkey.keep.BuildConfig
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.storage.toSelection
import io.privkey.keep.storage.toSignPolicy
import io.privkey.keep.uniffi.SignPolicySelection
import io.privkey.keep.uniffi.SignPolicyStore

private const val TAG = "AppSignPolicyOverrides"

/**
 * Per-app sign-policy overrides, mid-move from the legacy Room `nip55_app_settings`
 * row into the core-owned store.
 *
 * A per-app override is normally STRICTER than the global policy (an app pinned to
 * Manual while the global is Auto), so losing one silently drops that app onto the
 * looser global and auto-approves signing it should not get. Every path here is built
 * around that: reads consult both stores, a write only drops the legacy value once
 * the core has reported the new one back, and the migration never overwrites the core.
 *
 * The content provider and the UI both go through here so the two cannot drift.
 */
object AppSignPolicyOverrides {

    /**
     * The override in force: the core store first, the legacy Room row as a fallback.
     * Yields null only when neither store holds one, so an incomplete or failed
     * migration can never drop an app onto the looser global policy.
     */
    suspend fun override(
        core: SignPolicyStore?,
        permissions: PermissionStore,
        callerPackage: String
    ): SignPolicySelection? =
        core?.appOverride(callerPackage) ?: legacyOverride(permissions, callerPackage)

    /**
     * Override -> global -> Manual, the precedence the signing path has always used.
     *
     * Deliberately not the core's `effectivePolicy`, which cannot see the Room
     * fallback and would report the global for any app whose override has not been
     * migrated yet. Switch to it once the fallback below is retired.
     */
    suspend fun effectivePolicy(
        core: SignPolicyStore?,
        permissions: PermissionStore,
        callerPackage: String
    ): SignPolicySelection =
        override(core, permissions, callerPackage)
            ?: core?.globalPolicy()
            ?: SignPolicySelection.MANUAL

    /**
     * Writes [selection] to the core (null clears the override) and mirrors the same
     * value into the Room row.
     *
     * Room is a mirror, not a stale leftover: a clear nulls both stores, so the dual
     * read above cannot resurrect an override the user has cleared or loosened. The
     * mirror is what keeps the Room row usable as the lifecycle index for overrides,
     * which is how the expiry sweep and the account-switch wipe still find the
     * packages whose core override has to go (see [PermissionStore.cleanupExpired]
     * and [PermissionStore.clearAllAppSettings]). Clearing Room here instead would
     * make core overrides invisible to Kotlin and immortal.
     *
     * Room is only touched once the core reports the new value back: the core's
     * storage trait cannot signal a failed write, and mirroring a write that did not
     * land would make the two stores disagree with the losing side (Room) holding the
     * value the user thinks is in force. Leaving both untouched keeps the app on what
     * it already had, never on something looser.
     */
    suspend fun setOverride(
        core: SignPolicyStore?,
        permissions: PermissionStore,
        callerPackage: String,
        selection: SignPolicySelection?
    ) {
        val ordinal = selection?.toSignPolicy()?.ordinal
        if (core == null) {
            // No core store this session (init failed). Keep Room authoritative
            // rather than dropping the override on the floor.
            permissions.setAppSignPolicyOverride(callerPackage, ordinal)
            return
        }
        core.setAppOverride(callerPackage, selection)
        if (core.appOverride(callerPackage) == selection) {
            permissions.setAppSignPolicyOverride(callerPackage, ordinal)
        }
    }

    /**
     * Best-effort copy of the legacy Room overrides into the core, run at startup.
     * Idempotent: a package the core already holds an override for is left alone, so
     * a re-run can never clobber a newer choice with the stale Room value.
     *
     * The Room values stay on disk: [override] still falls back to them, and they are
     * the index the lifecycle sweeps use. A failure here is therefore harmless, it
     * just leaves the fallback doing the work.
     */
    suspend fun migrateLegacyOverrides(core: SignPolicyStore, permissions: PermissionStore) {
        runCatching {
            for (settings in permissions.getAllAppSettings()) {
                val ordinal = settings.signPolicyOverride ?: continue
                // An expired row is on its way out via the expiry sweep; copying it
                // would turn a time-boxed override into a permanent one. The Room
                // fallback still covers it until the sweep removes it.
                if (settings.isExpired()) continue
                if (core.appOverride(settings.callerPackage) != null) continue
                core.setAppOverride(
                    settings.callerPackage,
                    SignPolicy.fromOrdinal(ordinal).toSelection()
                )
            }
        }.onFailure {
            if (BuildConfig.DEBUG) Log.w(TAG, "Sign-policy override migration failed", it)
        }
    }

    // An out-of-range stored ordinal resolves to Manual, the strictest tier.
    private suspend fun legacyOverride(
        permissions: PermissionStore,
        callerPackage: String
    ): SignPolicySelection? =
        permissions.getAppSignPolicyOverride(callerPackage)
            ?.let { SignPolicy.fromOrdinal(it).toSelection() }
}
