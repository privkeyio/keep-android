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
 * around that: reads consult both stores and resolve a disagreement to the stricter
 * side, a write only touches the second store once the first has confirmed, and the
 * migration never overwrites the core.
 *
 * The content provider and the UI both go through here so the two cannot drift.
 */
object AppSignPolicyOverrides {

    /**
     * The override in force, read from both stores. Yields null only when neither
     * holds one, so an incomplete or failed migration can never drop an app onto the
     * looser global policy.
     *
     * When the two disagree the STRICTER value wins (Manual < Basic < Auto), not the
     * core. The stores can only disagree because a write landed in one and not the
     * other, and there is no way to tell which side is the newer intent: the core's
     * prefs backend swallows write failures and discards `commit()`'s result, so a
     * value can be current in memory and absent on disk, and a session where the core
     * store failed to construct writes to Room alone (the migration then skips that
     * package forever, because the core already "knows" it). Core-first would let a
     * stale looser value win in every one of those cases. Picking the stricter side
     * costs the user a re-pick at worst; picking the looser one silently auto-approves
     * signing the app was pinned away from.
     */
    suspend fun override(
        core: SignPolicyStore?,
        permissions: PermissionStore,
        callerPackage: String
    ): SignPolicySelection? =
        stricter(core?.appOverride(callerPackage), legacyOverride(permissions, callerPackage))

    private fun stricter(
        first: SignPolicySelection?,
        second: SignPolicySelection?
    ): SignPolicySelection? {
        if (first == null) return second
        if (second == null) return first
        // Via SignPolicy so the ordering goes through the checked mapping rather than
        // assuming the FFI enum's declaration order.
        return if (first.toSignPolicy().ordinal <= second.toSignPolicy().ordinal) first else second
    }

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
     * On a SET the core goes first and Room is only touched once the core reports the
     * new value back, because the core's storage trait cannot signal a failed write.
     *
     * On a CLEAR the order is reversed: the mirror goes first, and the core is left
     * alone if that throws. Clearing the core first and then failing on the mirror
     * would leave the stale override as the only copy, which [override] hands straight
     * back and [migrateLegacyOverrides] then copies into the core permanently, since
     * the core no longer holds anything to skip on. Mirror-first turns that into "the
     * clear did not happen": both stores still agree on the old value, the caller sees
     * the throw, and a re-read shows the override still in force.
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
            // rather than dropping the override on the floor. The stricter-wins rule
            // in [override] stops a stale core value from outranking this later.
            permissions.setAppSignPolicyOverride(callerPackage, ordinal)
            return
        }
        if (selection == null) {
            permissions.setAppSignPolicyOverride(callerPackage, null)
            core.setAppOverride(callerPackage, null)
            return
        }
        core.setAppOverride(callerPackage, selection)
        if (core.appOverride(callerPackage) != selection) return
        // A failed mirror write must not propagate: the core already holds the new
        // value, so the write did take effect. The stores diverge until the next
        // write, and stricter-wins bounds that to "no looser than either side".
        runCatching { permissions.setAppSignPolicyOverride(callerPackage, ordinal) }
            .onFailure { if (BuildConfig.DEBUG) Log.w(TAG, "Sign-policy mirror write failed", it) }
    }

    /**
     * Best-effort copy of the legacy Room overrides into the core, run at startup.
     * Idempotent: a package the core already holds an override for is left alone, so
     * a re-run can never clobber a newer choice with the stale Room value. Skipping
     * those packages is safe precisely because [override] resolves a disagreement to
     * the stricter side rather than to whatever the core happens to hold.
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
