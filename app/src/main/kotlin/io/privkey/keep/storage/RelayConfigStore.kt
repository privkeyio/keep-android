package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class RelayConfigStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_relay_config"
        private const val KEY_RELAYS = "relay_urls"
        private const val RELAY_SEPARATOR = "\n"
        internal val RELAY_URL_REGEX = Regex("^wss://[a-zA-Z0-9.-]+(:\\d{1,5})?(/[a-zA-Z0-9._~:/?#\\[\\]@!\$&'()*+,;=-]*)?$")
    }

    private val prefs: SharedPreferences = run {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun getRelays(): List<String> {
        val stored = prefs.getString(KEY_RELAYS, null) ?: return emptyList()
        return stored.split(RELAY_SEPARATOR).filter { it.isNotBlank() }
    }

    fun setRelays(relays: List<String>) {
        prefs.edit()
            .putString(KEY_RELAYS, relays.joinToString(RELAY_SEPARATOR))
            .apply()
    }

    fun addRelay(relay: String): Boolean {
        if (!relay.matches(RELAY_URL_REGEX)) return false
        val current = getRelays().toMutableList()
        if (current.contains(relay)) return false
        current.add(relay)
        setRelays(current)
        return true
    }

    fun removeRelay(relay: String): Boolean {
        val current = getRelays().toMutableList()
        if (!current.remove(relay)) return false
        setRelays(current)
        return true
    }
}
