package io.privkey.keep.nip46

import android.content.SharedPreferences

/**
 * The account-switch mark that makes the next bunker start revoke every remembered grant.
 * Held in memory as well as in [prefs], so a mark that could not be saved still applies to
 * every start in this process. A start clears it only if no switch set it again after the
 * start read it, since that switch's grants may postdate the revoke.
 *
 * A save that fails stops the change: a switch or delete of the active account, or a store
 * that may replace it, which saves the mark before it runs. Ceiling: a power cut can roll
 * back a save that reported success. The next start then restores the previous account's
 * remembered grants, and the switch's rotation does not keep a client holding one out, since
 * the bunker key is public. Goes with the start-time revoke.
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

    /**
     * Sets the mark ahead of a change that may switch accounts. Returns a withdraw for when it
     * did not, or null when a mark was already pending, since only a start may clear that one.
     */
    @Synchronized
    fun setAhead(): (() -> Unit)? {
        val wasSet = isSet()
        set()
        if (wasSet) return null
        val token = requests
        return { withdraw(token) }
    }

    @Synchronized
    private fun withdraw(token: Int) {
        if (requests != token) return
        check(prefs.edit().remove(BunkerService.KEY_REVOKE_ALL_ON_START).commit()) { "could not withdraw the revoke-all mark" }
        pending = false
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
