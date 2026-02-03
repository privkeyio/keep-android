package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.net.InetAddress
import java.net.URI

class BunkerConfigStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_bunker_config"
        private const val KEY_RELAYS = "bunker_relay_urls"
        private const val KEY_ENABLED = "bunker_enabled"
        private const val KEY_AUTHORIZED_CLIENTS = "authorized_clients"
        private const val LIST_SEPARATOR = "\n"
        internal const val MAX_RELAYS = 5
        internal const val MAX_AUTHORIZED_CLIENTS = 50
        internal val RELAY_URL_REGEX = Regex("^wss://[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:\\d{1,5})?(/[a-zA-Z0-9._~:/?#\\[\\]@!\$&'()*+,;=-]*)?$")
        internal val HEX_PUBKEY_REGEX = Regex("^[a-fA-F0-9]{64}$")

        internal fun isInternalHost(url: String): Boolean {
            val host = runCatching {
                val uri = URI(url)
                uri.host?.removeSurrounding("[", "]")
            }.getOrNull() ?: return true

            if (host.equals("localhost", ignoreCase = true)) return true

            val addr = runCatching { InetAddress.getByName(host) }.getOrNull() ?: return true
            return isInternalAddress(addr)
        }

        internal fun isInternalAddress(addr: InetAddress): Boolean {
            return addr.isLoopbackAddress ||
                addr.isLinkLocalAddress ||
                addr.isSiteLocalAddress ||
                addr.isAnyLocalAddress ||
                isIPv4MappedPrivate(addr)
        }

        private fun isIPv4MappedPrivate(addr: InetAddress): Boolean {
            val bytes = addr.address
            if (bytes.size != 16) return false
            for (i in 0..9) {
                if (bytes[i] != 0.toByte()) return false
            }
            if (bytes[10] != 0xFF.toByte() || bytes[11] != 0xFF.toByte()) return false
            val ipv4 = byteArrayOf(bytes[12], bytes[13], bytes[14], bytes[15])
            val mappedAddr = runCatching { InetAddress.getByAddress(ipv4) }.getOrNull() ?: return false
            return mappedAddr.isLoopbackAddress ||
                mappedAddr.isLinkLocalAddress ||
                mappedAddr.isSiteLocalAddress
        }
    }

    private val authLock = Any()

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
        return stored.split(LIST_SEPARATOR).filter { it.isNotBlank() }
    }

    fun setRelays(relays: List<String>) {
        val validated = relays
            .filter { it.matches(RELAY_URL_REGEX) && !isInternalHost(it) }
            .take(MAX_RELAYS)
        prefs.edit()
            .putString(KEY_RELAYS, validated.joinToString(LIST_SEPARATOR))
            .apply()
    }

    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false)

    fun setEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENABLED, enabled).apply()
    }

    fun getAuthorizedClients(): Set<String> {
        val stored = prefs.getString(KEY_AUTHORIZED_CLIENTS, null) ?: return emptySet()
        return stored.split(LIST_SEPARATOR)
            .filter { it.isNotBlank() && it.matches(HEX_PUBKEY_REGEX) }
            .toSet()
    }

    fun isClientAuthorized(pubkey: String): Boolean {
        synchronized(authLock) {
            return getAuthorizedClients().contains(pubkey.lowercase())
        }
    }

    fun authorizeClient(pubkey: String): Boolean {
        if (!pubkey.matches(HEX_PUBKEY_REGEX)) return false
        synchronized(authLock) {
            val clients = getAuthorizedClients().toMutableSet()
            if (clients.size >= MAX_AUTHORIZED_CLIENTS) return false
            if (clients.contains(pubkey.lowercase())) return true
            clients.add(pubkey.lowercase())
            saveAuthorizedClients(clients)
            return true
        }
    }

    fun revokeClient(pubkey: String) {
        synchronized(authLock) {
            val clients = getAuthorizedClients().toMutableSet()
            clients.remove(pubkey.lowercase())
            saveAuthorizedClients(clients)
        }
    }

    private fun saveAuthorizedClients(clients: Set<String>) {
        prefs.edit()
            .putString(KEY_AUTHORIZED_CLIENTS, clients.joinToString(LIST_SEPARATOR))
            .apply()
    }

    fun revokeAllClients() {
        prefs.edit().remove(KEY_AUTHORIZED_CLIENTS).apply()
    }
}
