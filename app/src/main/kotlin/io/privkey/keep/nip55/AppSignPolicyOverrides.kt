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
 * Per-app sign-policy overrides.
 *
 * A per-app override is normally STRICTER than the global policy (an app pinned to
 * Manual while the global is Auto), so serving the wrong value auto-approves signing
 * the app was pinned away from. That one risk shapes everything here.
 *
 * The core-owned store holds the tier, and it is the only thing that does. The Room
 * `nip55_app_settings` row holds what the core cannot: the window the override expires at,
 * since the core keeps no expiry, and a record of the pinning that the lifecycle sweeps
 * can enumerate, since the core store cannot be listed (it answers for one package, it
 * just cannot produce the set of them). The row also carries the tier, but only as the source
 * [migrateLegacyOverrides] copies from; resolution never reads it as the policy, so the
 * two cannot disagree in a way that has to be reconciled.
 *
 * Every failure therefore has the same answer. A pinned app whose tier the core cannot
 * produce is unknown rather than unpinned, and resolves to Manual: not to the global,
 * which may be looser than the tier the user chose. A write that does not durably land
 * pins Manual as well. Unknown means strict, so a fault tightens rather than loosens.
 *
 * The content provider and the UI both go through here so the two cannot drift.
 */
object AppSignPolicyOverrides {

    /** The override in force, or null when the app has none. */
    suspend fun override(
        core: SignPolicyStore?,
        permissions: PermissionStore,
        callerPackage: String
    ): SignPolicySelection? = resolve(core, permissions, callerPackage).getOrNull()

    /**
     * Override -> global -> Manual, the precedence the signing path has always used.
     *
     * Deliberately not the core's `effectivePolicy`, which cannot see the row and so
     * cannot tell an app that has no override from one whose tier has not been migrated
     * yet. Switch to it once every override is known to live in the core.
     */
    suspend fun effectivePolicy(
        core: SignPolicyStore?,
        permissions: PermissionStore,
        callerPackage: String
    ): SignPolicySelection {
        val resolved = resolve(core, permissions, callerPackage)
        // The row read faulted, so whether this app is pinned at all is unknown. Falling
        // to the strictest tier costs a prompt; falling to the global would hand the app
        // whatever that happens to be.
        if (resolved.isFailure) return SignPolicySelection.MANUAL
        return resolved.getOrNull()
            ?: core?.let { runCatching { it.globalPolicy() }.getOrNull() }
            ?: SignPolicySelection.MANUAL
    }

    private suspend fun resolve(
        core: SignPolicyStore?,
        permissions: PermissionStore,
        callerPackage: String
    ): Result<SignPolicySelection?> = runCatching {
        val row = permissions.getAppSettings(callerPackage)
        // No row, or a row carrying no override, means the app is not pinned. A lapsed
        // window retires it: the row is the only record of when the override was due to
        // end, and the signing path applies the policy before it evaluates app expiry, so
        // an override left in force here would auto-approve on the way past.
        if (row?.signPolicyOverride == null || row.isExpired()) return@runCatching null
        // The row says this app is pinned; the core holds the tier. A tier the core
        // cannot produce is unknown rather than absent, whether because it has not
        // migrated, because a write never landed, or because the read faulted.
        core?.appOverride(callerPackage) ?: SignPolicySelection.MANUAL
    }

    /**
     * Pins [callerPackage] to [selection], or clears its override when null.
     *
     * The core write has to durably land before the row is updated. `setAppOverride`
     * returns its backing store's `commit()` result, which is the only signal that
     * separates "on disk" from "in the in-memory map a failed commit left behind"; a
     * read-back cannot, because the encrypted prefs serve that cached value.
     *
     * An unconfirmed write does not say which value is stored, so it is repaired rather
     * than ignored: the core may hold the old tier, or serve the new one from memory
     * while its disk still holds the old. Pinning Manual covers every one of those. It is
     * best effort, not a floor: the row's tier is not read, so if the repair does not land
     * either, the core keeps serving whatever it has. The screen reports the tier that
     * resolved rather than the one that was asked for, so the user can pick again.
     *
     * The row write is not guarded. It is the index, so a row that cannot be written
     * means the change did not take, and the screen reports that too.
     */
    suspend fun setOverride(
        core: SignPolicyStore?,
        permissions: PermissionStore,
        callerPackage: String,
        selection: SignPolicySelection?
    ) {
        if (core == null) {
            // No core store this session, so there is nowhere to put the tier and nothing
            // would honor it. Record the app as pinned at Manual, which is what it
            // resolves to anyway while the store is missing, rather than recording a tier
            // that cannot take effect. A looser choice is simply refused until the store
            // is back.
            permissions.setAppSignPolicyOverride(callerPackage, SignPolicy.MANUAL.ordinal)
            return
        }
        if (selection == null) {
            // Dropping the row IS the clear, because a tier with no row to index it is
            // inert. Doing it first also means a core clear that does not land cannot be
            // undone later: [migrateLegacyOverrides] reads the row's tier, so a row left
            // behind would be copied back into the empty slot at the next startup and
            // silently revert the clear.
            permissions.setAppSignPolicyOverride(callerPackage, null)
            // Hygiene, not the clear itself: drop the now-unreachable tier so nothing
            // picks it up again.
            wrote(core, callerPackage, null)
            return
        }
        // Index first, for the mirror of that reason: an unindexed tier is inert, while a
        // row whose tier the core cannot produce resolves to Manual, so a tier write that
        // does not land fails closed instead of dropping the app onto the global.
        permissions.setAppSignPolicyOverride(callerPackage, selection.toSignPolicy().ordinal)
        if (wrote(core, callerPackage, selection)) return
        // Unconfirmed: `false` does not say which value is stored, so pin Manual. If that
        // does not land either, the core goes on serving whatever it has and the settings
        // screen reports that rather than the tier that was asked for.
        wrote(core, callerPackage, SignPolicySelection.MANUAL)
    }

    /**
     * Whether the core durably recorded [selection]. A throw counts as a failed write,
     * so a faulting store is repaired like any other unconfirmed write rather than
     * surfacing to the caller: the settings UI resolves this from a coroutine.
     */
    private fun wrote(
        core: SignPolicyStore,
        callerPackage: String,
        selection: SignPolicySelection?
    ): Boolean = runCatching { core.setAppOverride(callerPackage, selection) }.getOrDefault(false)

    /**
     * Copies the row values into the core at startup, which is what moves a pinned app
     * from resolving Manual to resolving its chosen tier.
     *
     * Idempotent: a package the core already holds a tier for is left alone, so a re-run
     * cannot clobber a newer choice with the row's copy.
     */
    suspend fun migrateLegacyOverrides(core: SignPolicyStore, permissions: PermissionStore) {
        runCatching {
            for (settings in permissions.getAllAppSettings()) {
                val ordinal = settings.signPolicyOverride ?: continue
                // An expired row is on its way out via the expiry sweep, and the core
                // keeps no expiry, so copying it would turn a time-boxed override into a
                // permanent one. It already resolves to nothing.
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
}
