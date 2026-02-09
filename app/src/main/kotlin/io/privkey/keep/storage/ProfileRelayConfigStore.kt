package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
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

    fun getRelays(): List<String> {
        val stored = prefs.getString(KEY_RELAYS, null) ?: return emptyList()
        return stored.split(RELAY_SEPARATOR).filter { it.isNotBlank() }
    }

    suspend fun setRelays(relays: List<String>) {
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
                .putString(KEY_RELAYS, validated.joinToString(RELAY_SEPARATOR))
                .commit()
        }
    }

    fun clearRelays() {
        prefs.edit().remove(KEY_RELAYS).commit()
    }
}
