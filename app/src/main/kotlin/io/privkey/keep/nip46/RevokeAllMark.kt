package io.privkey.keep.nip46

import android.content.SharedPreferences

/**
 * The account-switch mark that makes the next bunker start revoke every remembered grant.
 * Held in memory as well as in [prefs], so a mark that could not be saved still applies to
 * every start in this process. A start clears it only if no switch set it again after the
 * start read it, since that switch's grants may postdate the revoke.
 *
 * Ceiling: a save that failed, or one a power cut rolled back, is lost when the process
 * ends, and the next start then restores the previous account's remembered grants. The
 * switch's rotation still keeps those clients out unless it failed or was rolled back too.
 * A switch or delete of the active account stops when the save and the rotation both
 * failed; an import cannot. Goes with the start-time revoke.
 */
internal class RevokeAllMark(private val prefs: SharedPreferences) {
    private var pending = false
    private var requests = 0

    @Synchronized
    fun set() {
        requests++
        pending = true
        check(prefs.edit().putBoolean(BunkerService.KEY_REVOKE_ALL_ON_START, true).commit()) {
            "could not mark the grants for revocation"
        }
    }

    @Synchronized
    fun isSet(): Boolean = pending || prefs.getBoolean(BunkerService.KEY_REVOKE_ALL_ON_START, false)

    @Synchronized
    fun requestsSoFar(): Int = requests

    /** Clears the mark unless it was set again after [seen] was read, or [stillServing] says no. */
    @Synchronized
    fun clearIfUnchanged(seen: Int, stillServing: () -> Boolean): Boolean {
        if (requests != seen || !stillServing()) return false
        check(prefs.edit().remove(BunkerService.KEY_REVOKE_ALL_ON_START).commit()) { "could not clear the revoke-all mark" }
        pending = false
        return true
    }
}
