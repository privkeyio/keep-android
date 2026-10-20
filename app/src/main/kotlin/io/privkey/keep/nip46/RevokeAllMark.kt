package io.privkey.keep.nip46

import android.content.SharedPreferences

/**
 * The account-switch mark that makes the next bunker start revoke every remembered grant.
 * Held in memory as well as in [prefs], so a mark that could not be saved still applies to
 * every start in this process. A start clears it only if no switch set it again after the
 * start read it, since that switch's grants may postdate the revoke.
 *
 * A change that may switch accounts saves the mark before it runs ([setAhead]), and then
 * makes it the switch's mark or withdraws it. While it is open a start still revokes, since
 * the core may already have switched, but leaves the saved mark in place. So a bunker that
 * restarts during a change that then fails has its grants revoked and its URL rotated for
 * nothing. A process that dies with a change open finds the mark saved.
 *
 * A save that fails stops the change: a switch or delete of the active account, or a store
 * that may replace it. Ceiling: a power cut can roll back a save that reported success. The
 * next start then restores the previous account's remembered grants, and the switch's
 * rotation does not keep a client holding one out, since the bunker key is public. Goes with
 * the start-time revoke.
 */
internal class RevokeAllMark(private val prefs: SharedPreferences) {
    private var pending = false
    private var requests = 0
    private var open = 0

    @Synchronized
    fun set() {
        requests++
        pending = true
        check(prefs.edit().putBoolean(BunkerService.KEY_REVOKE_ALL_ON_START, true).commit()) {
            "could not mark the grants for revocation"
        }
    }

    /**
     * Saves the mark ahead of a change that may switch accounts. Returns what the change calls
     * once done, with whether it switched. Throws, leaving nothing open, when it is not saved.
     */
    @Synchronized
    fun setAhead(): (switched: Boolean) -> Unit {
        // A mark only open changes saved is not a switch's yet.
        if (pending || (open == 0 && prefs.getBoolean(BunkerService.KEY_REVOKE_ALL_ON_START, false))) pending = true
        if (!prefs.edit().putBoolean(BunkerService.KEY_REVOKE_ALL_ON_START, true).commit()) {
            if (!pending && open == 0) prefs.edit().remove(BunkerService.KEY_REVOKE_ALL_ON_START).commit()
            throw IllegalStateException("could not mark the grants for revocation")
        }
        open++
        return { switched -> finishAhead(switched) }
    }

    @Synchronized
    private fun finishAhead(switched: Boolean) {
        open--
        if (switched) {
            requests++
            pending = true
        } else if (open == 0 && !pending) {
            check(prefs.edit().remove(BunkerService.KEY_REVOKE_ALL_ON_START).commit()) { "could not withdraw the revoke-all mark" }
        }
    }

    @Synchronized
    fun isSet(): Boolean = pending || prefs.getBoolean(BunkerService.KEY_REVOKE_ALL_ON_START, false)

    @Synchronized
    fun requestsSoFar(): Int = requests

    /**
     * Clears the mark unless it was set again after [seen] was read, or [stillServing] says no.
     * The saved mark stays while a change is open.
     */
    @Synchronized
    fun clearIfUnchanged(seen: Int, stillServing: () -> Boolean): Boolean {
        if (requests != seen || !stillServing()) return false
        if (open == 0) check(prefs.edit().remove(BunkerService.KEY_REVOKE_ALL_ON_START).commit()) { "could not clear the revoke-all mark" }
        pending = false
        return true
    }
}
