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

    /** The normalized whitelisted relay hosts, sorted for stable display. */
    fun getHosts(): List<String> =
        (prefs.getStringSet(KEY_HOSTS, emptySet()) ?: emptySet()).sorted()

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
