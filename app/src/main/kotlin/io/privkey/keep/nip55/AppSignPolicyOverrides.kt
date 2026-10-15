package io.privkey.keep.nip55

import android.content.SharedPreferences
import android.util.Log
import io.privkey.keep.BuildConfig
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.storage.SignPolicySelectionPrefs
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
 * The core-owned store owns the tier: it is what a write has to land in, and what the
 * signing path reads. The Room `nip55_app_settings` row carries three things the core
 * cannot: the window the override expires at, since the core keeps no expiry, a record of
 * the pinning that the lifecycle sweeps can enumerate, since the core store cannot be
 * listed (it answers for one package, it just cannot produce the set of them), and the
 * last tier the user chose, which both seeds [migrateLegacyOverrides] and serves as the
 * strictness floor below.
 *
 * Resolution takes the stricter of the two, which makes the row a floor rather than a
 * second opinion to reconcile: a write that reached one store and not the other cannot
 * widen the app, and the floor never has to decide which side is newer. When only one
 * side knows of an override at all, the tier exists but is unknown, and that resolves to
 * Manual rather than to the global, which may be looser than the tier the user chose, and
 * rather than to whichever side answered, which may be the stale one. So a partial write,
 * an unmigrated row and a read fault all tighten rather than loosen.
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
        // A lapsed window retires the override: the row is the only record of when it was
        // due to end, and the signing path applies the policy before it evaluates app
        // expiry, so an override left in force here would auto-approve on the way past.
        if (row != null && row.isExpired()) return@runCatching null
        // An out-of-range stored ordinal resolves to Manual, the strictest tier.
        val fromRow = row?.signPolicyOverride?.let { SignPolicy.fromOrdinal(it).toSelection() }
        val fromCore = core?.appOverride(callerPackage)
        // Neither side knows of one: the app is not pinned, so the global applies.
        if (fromRow == null && fromCore == null) return@runCatching null
        // Exactly one side knows of one, so a tier exists but which one is unknown: the
        // row has not been migrated, or a write reached one store and not the other, or a
        // read faulted (the prefs layer returns the default when a value cannot be
        // decrypted, so unreadable is indistinguishable from absent). Resolve the
        // strictest tier rather than the global, which may be looser than what the user
        // chose, and rather than the one side that did answer, which may be the stale one.
        if (fromRow == null || fromCore == null) return@runCatching SignPolicySelection.MANUAL
        stricter(fromCore, fromRow)
    }

    /**
     * Never looser than either side.
     *
     * The core holds the tier that durably landed and the row holds the last choice that
     * was recorded, so a write that reached one and not the other must not widen the app.
     * `setAppOverride` returning `false` is exactly that case, and it does not say which
     * value is stored: the prefs layer applies to its in-memory map before the disk write,
     * so the core can serve the new tier for the rest of the session while its file still
     * holds the old one, and the next process start would otherwise read the old tier back
     * with nothing to correct it.
     *
     * This is a floor, not a reconciliation. It never has to decide which side is newer,
     * which is what made the previous resolve-the-disagreement scheme hard to reason
     * about: the strictest of what either store knows is always a safe answer.
     */
    private fun stricter(
        first: SignPolicySelection,
        second: SignPolicySelection
    ): SignPolicySelection =
        if (first.toSignPolicy().ordinal <= second.toSignPolicy().ordinal) first else second

    /**
     * Pins [callerPackage] to [selection], or clears its override when null.
     *
     * `setAppOverride` returns its backing store's `commit()` result, which is the only
     * signal that separates "on disk" from "in the in-memory map a failed commit left
     * behind"; a read-back cannot, because the encrypted prefs serve that cached value.
     * Which store is written first differs by direction, for the reasons at each branch.
     *
     * An unconfirmed write does not say which value is stored, so Manual is pinned as a
     * best-effort repair: the core may hold the old tier, or serve the new one from memory
     * while its disk still holds the old. The repair can fail too, which is why the floor
     * in [resolve] rather than the repair is what actually bounds this: the row holds the
     * tier that was asked for, so the app can never resolve looser than it.
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
        if (selection == null) {
            // Drop the row first. A core clear that does not land then leaves a tier
            // known to one side only, which resolves to Manual: the chosen tier is gone,
            // which is what the user asked for, and the leftover cannot widen anything.
            // Keeping the row instead would let [migrateLegacyOverrides] copy its tier
            // back into the empty slot at the next startup and silently revert the clear.
            permissions.setAppSignPolicyOverride(callerPackage, null)
            // Hygiene, not the clear itself: drop the now-unreachable tier so nothing
            // picks it up again. Nothing to drop when there is no store this session.
            if (core != null) wrote(core, callerPackage, null)
            return
        }
        if (core == null) {
            // No core store this session, so there is nowhere to put the tier and nothing
            // would honor it. Record the app as pinned at Manual, which is what it
            // resolves to anyway while the store is missing, rather than recording a tier
            // that cannot take effect. A looser choice is simply refused until the store
            // is back.
            permissions.setAppSignPolicyOverride(callerPackage, SignPolicy.MANUAL.ordinal)
            return
        }
        // Index first, so a tier write that does not land leaves the app pinned-but-
        // unknown, which resolves to Manual rather than dropping it onto the global.
        //
        // A row write that THROWS must not skip the tier write, though. The floor means a
        // core holding the new tier against a row holding the old one resolves to the
        // stricter of the two, so attempting the tier write can only tighten: a
        // tightening still takes effect, and a loosening is refused because the old row
        // value wins. Returning early here instead would leave both stores on the old
        // tier and silently lose the tightening, which is what the previous ordering did.
        val rowFailure = runCatching {
            permissions.setAppSignPolicyOverride(callerPackage, selection.toSignPolicy().ordinal)
        }.exceptionOrNull()
        if (!wrote(core, callerPackage, selection)) {
            // Unconfirmed: `false` does not say which value is stored, so pin Manual. If
            // that does not land either, the floor still bounds the app by whichever tier
            // each store holds.
            wrote(core, callerPackage, SignPolicySelection.MANUAL)
        }
        // Reported after the tier write, so the screen still tells the user the change did
        // not fully take and re-reads what actually resolved.
        rowFailure?.let { throw it }
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
     * Gated on persisted markers in [markers] rather than on the core looking empty for a
     * package. The encrypted-prefs layer returns the default when a value cannot be
     * decrypted, so an unreadable tier is indistinguishable from an absent one, and a
     * second run that read it as absent would copy the row's tier over a stricter one the
     * core durably holds: `setOverride` pins Manual in the core when its write is
     * unconfirmed while the row keeps the tier the user asked for, so core-stricter-than-
     * row is a state this code produces deliberately. The absence check stays as the
     * second line, but it is not what bounds this.
     *
     * Each package's marker is written before its copy is attempted, and a package whose
     * marker cannot be persisted is skipped rather than copied unrecorded: an attempt that
     * left no record is the only way a package gets copied twice. The run-wide marker is
     * then set only once every row was attempted, so a run that threw partway leaves the
     * packages it never reached to a later startup instead of abandoning them. The
     * per-package markers are what make that retry safe.
     *
     * Skipping is always the strict direction, and it costs a prompt rather than widening
     * anything. What it costs differs by case. A package no run has reached yet is copied by
     * a later startup. A package whose marker is already recorded gets no later copy at all:
     * it resolves Manual until the user picks its tier again. That is the accepted price of
     * closing the double-copy window, and it includes the plain case of the process being
     * killed between the marker commit and the write, with no fault involved at all. A
     * two-phase in-progress marker would not buy anything, because in-progress is precisely
     * the unknown outcome that must not be retried.
     *
     * One widening window is left, and the markers do not close it: for a package no run
     * has attempted yet, a core that reads as absent because its value would not decrypt
     * gets the row's tier copied over whatever it durably holds, which an unconfirmed
     * `setOverride` write may have left stricter. Closing that needs a store that can tell
     * an absent value from an unreadable one.
     */
    suspend fun migrateLegacyOverrides(
        core: SignPolicyStore,
        permissions: PermissionStore,
        markers: SharedPreferences
    ) {
        // Installs that completed this copy before the markers became per-package have
        // only this one, and none of the per-package ones. Honoring it first is what keeps
        // them from being migrated a second time.
        if (markers.getBoolean(SignPolicySelectionPrefs.APP_OVERRIDE_MIGRATION_MARKER, false)) return

        val everyRowAttempted = runCatching {
            var complete = true
            for (settings in permissions.getAllAppSettings()) {
                // Cheap filter on the snapshot. What actually gets copied is the fresh read
                // below, which is the authority.
                if (settings.signPolicyOverride == null) continue
                // The snapshot can be well out of date by the time the Keystore writes in
                // this loop reach this package, so the row is read again here. A user who
                // tightened the app in the meantime must not have the stale, looser choice
                // written into the core behind them. The floor in [resolve] is what keeps
                // that from widening anything today, but only because nothing reads the
                // core's tier without the row beside it.
                val current = permissions.getAppSettings(settings.callerPackage)
                val ordinal = current?.signPolicyOverride
                // An expired row is on its way out via the expiry sweep, and the core
                // keeps no expiry, so copying it would turn a time-boxed override into a
                // permanent one. It already resolves to nothing.
                //
                // Not an attempt, so it must not count as one: the sweep keeps an expired
                // row whose core clear it could not confirm, and `setAppExpiry` can later
                // refresh that row's window while preserving its tier. Claiming the
                // run-wide marker here would leave that live row's tier uncopyable. A row
                // that went away entirely drops out of the next snapshot, so it cannot
                // withhold the marker for good.
                if (current == null || ordinal == null || current.isExpired()) {
                    complete = false
                    continue
                }
                val marker = SignPolicySelectionPrefs.appOverrideMarkerKey(settings.callerPackage)
                // Checked before the core read, which costs a Keystore round trip.
                if (markers.getBoolean(marker, false)) continue
                if (!markers.edit().putBoolean(marker, true).commit()) {
                    // `commit()` applies to the in-memory map before it reports the disk
                    // write, and a write serializes the whole map, so the marker has to be
                    // taken back out: left there, the next successful commit in this run
                    // persists a marker for a package nothing was copied for, and that
                    // package is then skipped forever. The removal only has to reach memory
                    // to do its job, which is why its own result is not checked.
                    markers.edit().remove(marker).commit()
                    if (BuildConfig.DEBUG) Log.w(TAG, "Could not record a migration attempt; deferring one package")
                    complete = false
                    continue
                }
                // A read that could not answer is not a licence to copy: the tier it failed
                // to produce may be stricter than this row's. Caught per package so one
                // package's fault does not abandon the rest of the run.
                val existing = runCatching { core.appOverride(settings.callerPackage) }
                if (existing.isFailure || existing.getOrNull() != null) continue
                // A copy that did not confirm pins Manual instead of being retried. `false`
                // does not say which value is stored, and the platform prefs serve the new
                // one from memory for the rest of the process either way, so a retry on a
                // later start is a copy whose outcome is already unknown: if the core
                // durably holds the stricter Manual that an unconfirmed `setOverride` write
                // pinned, and the read of it faults, the retry widens the app. Tightening
                // instead costs the user a re-pick.
                val tier = SignPolicy.fromOrdinal(ordinal).toSelection()
                if (!wrote(core, settings.callerPackage, tier)) {
                    wrote(core, settings.callerPackage, SignPolicySelection.MANUAL)
                }
            }
            complete
        }.onFailure {
            if (BuildConfig.DEBUG) Log.w(TAG, "Sign-policy override migration failed", it)
        }.getOrDefault(false)

        if (everyRowAttempted) {
            // The per-package markers are dead once this lands, because the return above
            // happens before any of them is read. Dropped in the same editor so the file
            // stops carrying a standing list of which apps the user pinned, and so the
            // run-wide marker cannot be set without them going with it.
            val edit = markers.edit()
                .putBoolean(SignPolicySelectionPrefs.APP_OVERRIDE_MIGRATION_MARKER, true)
            markers.all.keys
                .filter { it.startsWith(SignPolicySelectionPrefs.APP_OVERRIDE_MARKER_PREFIX) }
                .forEach { edit.remove(it) }
            edit.commit()
        }
    }
}
