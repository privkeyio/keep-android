package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class ProfileRelayConfigStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_profile_relay_config"
        private const val KEY_RELAYS = "profile_relay_urls"
        private const val RELAY_SEPARATOR = "\n"
    }

    private val prefs: SharedPreferences = run {
        val newPrefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        LegacyPrefsMigration.migrateIfNeeded(context, PREFS_NAME, newPrefs)
    }

    fun getRelaysForAccount(accountKey: String): List<String> {
        val stored = prefs.getString(accountPrefsKey(accountKey), null) ?: return emptyList()
        return stored.split(RELAY_SEPARATOR).filter { it.isNotBlank() }
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
        val validated = withContext(Dispatchers.Default) {
            relays
                .filter {
                    it.matches(RelayConfigStore.RELAY_URL_REGEX) &&
                        !BunkerConfigStore.isInternalHost(it) &&
                        RelayConfigStore.isValidPort(it)
                }
                .take(RelayConfigStore.MAX_RELAYS)
        }
        withContext(Dispatchers.IO) {
            prefs.edit()
                .putString(prefsKey, validated.joinToString(RELAY_SEPARATOR))
                .commit()
        }
    }
}
