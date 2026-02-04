package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences

class RelayConfigStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_relay_config"
        private const val KEY_RELAYS = "relay_urls"
        private const val RELAY_SEPARATOR = "\n"
        internal const val MAX_RELAYS = 20
        internal val RELAY_URL_REGEX = Regex("^wss://[a-zA-Z0-9.-]+(:\\d{1,5})?(/[a-zA-Z0-9._~:/?#\\[\\]@!\$&'()*+,;=-]*)?$")
    }

    private val prefs: SharedPreferences = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    fun getRelays(): List<String> {
        val stored = prefs.getString(KEY_RELAYS, null) ?: return emptyList()
        return stored.split(RELAY_SEPARATOR).filter { it.isNotBlank() }
    }

    fun setRelays(relays: List<String>) {
        val validated = relays.filter { it.matches(RELAY_URL_REGEX) }.take(MAX_RELAYS)
        prefs.edit()
            .putString(KEY_RELAYS, validated.joinToString(RELAY_SEPARATOR))
            .apply()
    }
}
