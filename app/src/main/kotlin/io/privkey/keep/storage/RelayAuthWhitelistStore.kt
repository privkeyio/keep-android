package io.privkey.keep.storage

import android.content.Context
import io.privkey.keep.uniffi.nip55NormalizeRelayHost

/**
 * Global allowlist of relay hosts for NIP-42 (kind 22242) authentication. When the
 * list is non-empty it acts as a hard gate: a 22242 request whose relay is listed is
 * auto-accepted, one whose relay is not listed is auto-rejected, and an empty list
 * defers to normal per-app grant resolution. Entries are stored normalized (via the
 * Rust `nip55_normalize_relay_host`) so they compare consistently with request relays.
 */
class RelayAuthWhitelistStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_relay_auth_whitelist"
        private const val KEY_HOSTS = "relay_auth_whitelist_hosts"
        private const val MAX_ENTRIES = 256
    }

    private val prefs: ReadablePrefs = run {
        val newPrefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        LegacyPrefsMigration.migrateIfNeeded(context, PREFS_NAME, newPrefs)
    }

    /**
     * The normalized whitelisted relay hosts, sorted for stable display.
     *
     * Three-way, because this list is a hard gate and so "nothing is listed" and
     * "the list could not be read" must not arrive as one answer. The first
     * defers to per-app grant resolution by design; the second doing so would
     * let a grant the person gave earlier auto-approve a relay this list may
     * have been excluding, which is the one direction a deliberately configured
     * gate must never fail in.
     *
     * It replaced a [getStringSet] read whose empty default collapsed both, and
     * which left the two fault kinds behaving differently: a value that would
     * not decrypt read as an empty list, while a name that would not resolve
     * raised. Callers handled one or the other, never both.
     */
    fun readHosts(): PrefRead<List<String>> = when (val read = prefs.readStringSet(KEY_HOSTS)) {
        is PrefRead.Found -> PrefRead.Found(read.value.sorted())
        // Never configured and configured empty are the same thing to this gate,
        // so they are folded here and callers are left with two cases.
        PrefRead.Absent -> PrefRead.Found(emptyList())
        PrefRead.Unreadable -> PrefRead.Unreadable
    }

    /**
     * Normalizes [rawUrl] and adds it. Returns the normalized host on success, or null
     * if the input is not a usable relay host, the list is full, or the stored list
     * could not be read.
     */
    @Synchronized
    fun add(rawUrl: String): String? {
        val host = nip55NormalizeRelayHost(rawUrl) ?: return null
        val current = when (val read = prefs.readStringSet(KEY_HOSTS)) {
            is PrefRead.Found -> read.value.toMutableSet()
            PrefRead.Absent -> mutableSetOf()
            // This write replaces the whole entry, so going on from a read that failed
            // would leave the list holding nothing but the host being added, deleting
            // every relay the person had allowed.
            PrefRead.Unreadable -> return null
        }
        if (host !in current && current.size >= MAX_ENTRIES) return null
        current.add(host)
        if (!prefs.edit().putStringSet(KEY_HOSTS, current).commit()) return null
        return host
    }

    @Synchronized
    fun remove(host: String) {
        // Safe today only because the default is an empty set, which makes the removal
        // below find nothing and skip the write. Saying it outright so the guarantee
        // does not depend on that.
        val current = when (val read = prefs.readStringSet(KEY_HOSTS)) {
            is PrefRead.Found -> read.value.toMutableSet()
            PrefRead.Absent, PrefRead.Unreadable -> return
        }
        if (current.remove(host)) {
            prefs.edit().putStringSet(KEY_HOSTS, current).commit()
        }
    }
}
