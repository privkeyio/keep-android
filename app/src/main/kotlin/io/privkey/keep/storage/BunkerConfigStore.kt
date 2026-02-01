package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class BunkerConfigStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_bunker_config"
        private const val KEY_RELAYS = "bunker_relay_urls"
        private const val KEY_ENABLED = "bunker_enabled"
        private const val KEY_AUTHORIZED_CLIENTS = "authorized_clients"
        private const val RELAY_SEPARATOR = "\n"
        private const val CLIENT_SEPARATOR = "\n"
        internal const val MAX_RELAYS = 5
        internal const val MAX_AUTHORIZED_CLIENTS = 50
        internal val RELAY_URL_REGEX = Regex("^wss://[a-zA-Z0-9.-]+(:\\d{1,5})?(/[a-zA-Z0-9._~:/?#\\[\\]@!\$&'()*+,;=-]*)?$")
        internal val HEX_PUBKEY_REGEX = Regex("^[a-fA-F0-9]{64}$")
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
        val validated = relays.filter { it.matches(RELAY_URL_REGEX) }.take(MAX_RELAYS)
        prefs.edit()
            .putString(KEY_RELAYS, validated.joinToString(RELAY_SEPARATOR))
            .apply()
    }

    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false)

    fun setEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENABLED, enabled).apply()
    }

    fun getAuthorizedClients(): Set<String> {
        val stored = prefs.getString(KEY_AUTHORIZED_CLIENTS, null) ?: return emptySet()
        return stored.split(CLIENT_SEPARATOR)
            .filter { it.isNotBlank() && it.matches(HEX_PUBKEY_REGEX) }
            .toSet()
    }

    fun isClientAuthorized(pubkey: String): Boolean {
        return getAuthorizedClients().contains(pubkey.lowercase())
    }

    fun authorizeClient(pubkey: String): Boolean {
        if (!pubkey.matches(HEX_PUBKEY_REGEX)) return false
        val clients = getAuthorizedClients().toMutableSet()
        if (clients.size >= MAX_AUTHORIZED_CLIENTS) return false
        clients.add(pubkey.lowercase())
        prefs.edit()
            .putString(KEY_AUTHORIZED_CLIENTS, clients.joinToString(CLIENT_SEPARATOR))
            .apply()
        return true
    }

    fun revokeClient(pubkey: String) {
        val clients = getAuthorizedClients().toMutableSet()
        clients.remove(pubkey.lowercase())
        prefs.edit()
            .putString(KEY_AUTHORIZED_CLIENTS, clients.joinToString(CLIENT_SEPARATOR))
            .apply()
    }

    fun revokeAllClients() {
        prefs.edit().remove(KEY_AUTHORIZED_CLIENTS).apply()
    }
}
