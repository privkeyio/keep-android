package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext

class RelayConfigStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_relay_config"
        private const val KEY_RELAYS = "relay_urls"
        private const val RELAY_SEPARATOR = "\n"
        internal const val MAX_RELAYS = 20
        internal val RELAY_URL_REGEX = BunkerConfigStore.RELAY_URL_REGEX
        private val HOST_PORT_REGEX = Regex("^([^/:]+)(:(\\d+))?(/|$)")

        internal fun isValidPort(url: String): Boolean {
            val port = HOST_PORT_REGEX.find(url.removePrefix("wss://"))
                ?.groupValues?.get(3)?.takeIf { it.isNotEmpty() }?.toIntOrNull()
            return port == null || port in 1..65535
        }
        internal val DEFAULT_RELAYS = listOf(
            "wss://relay.primal.net/",
            "wss://relay.nsec.app/",
            "wss://relay.damus.io/",
            "wss://nos.lol/"
        )
    }

    private val prefs: SharedPreferences = run {
        val newPrefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        LegacyPrefsMigration.migrateIfNeeded(context, PREFS_NAME, newPrefs)
    }

    fun getRelays(): List<String> {
        val stored = prefs.getString(KEY_RELAYS, null) ?: return DEFAULT_RELAYS
        val relays = stored.split(RELAY_SEPARATOR).filter { it.isNotBlank() }
        return relays.ifEmpty { DEFAULT_RELAYS }
    }

    suspend fun setRelays(relays: List<String>) {
        saveRelays(KEY_RELAYS, relays)
    }

    fun getRelaysForAccount(accountKey: String): List<String> {
        val stored = prefs.getString(accountPrefsKey(accountKey), null)
        if (stored != null) return stored.split(RELAY_SEPARATOR).filter { it.isNotBlank() }
        val globalRelays = getRelays()
        if (globalRelays.isNotEmpty()) {
            prefs.edit().putString(accountPrefsKey(accountKey), globalRelays.joinToString(RELAY_SEPARATOR)).apply()
        }
        return globalRelays
    }

    suspend fun setRelaysForAccount(accountKey: String, relays: List<String>) {
        saveRelays(accountPrefsKey(accountKey), relays)
    }

    suspend fun deleteRelaysForAccount(accountKey: String) {
        withContext(Dispatchers.IO) {
            prefs.edit().remove(accountPrefsKey(accountKey)).commit()
        }
    }

    private fun accountPrefsKey(accountKey: String): String {
        val sanitized = sanitizeKey(accountKey)
        return "${KEY_RELAYS}_$sanitized"
    }

    private fun sanitizeKey(key: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(key.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    private suspend fun saveRelays(prefsKey: String, relays: List<String>) {
        withContext(Dispatchers.IO) {
            val candidates = relays
                .filter { it.matches(RELAY_URL_REGEX) && isValidPort(it) }
                .take(MAX_RELAYS)
            val validated = coroutineScope {
                candidates.map { url -> async { url.takeUnless { BunkerConfigStore.isInternalHost(it) } } }
                    .awaitAll()
                    .filterNotNull()
            }
            prefs.edit()
                .putString(prefsKey, validated.joinToString(RELAY_SEPARATOR))
                .commit()
        }
    }
}
