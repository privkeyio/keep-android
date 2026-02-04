package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class ProxyConfigStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_proxy_config"
        private const val KEY_ENABLED = "proxy_enabled"
        private const val KEY_HOST = "proxy_host"
        private const val KEY_PORT = "proxy_port"
        internal const val DEFAULT_HOST = "127.0.0.1"
        internal const val DEFAULT_PORT = 9050
        internal val ALLOWED_HOSTS = setOf("127.0.0.1", "localhost", "::1", "[::1]")

        fun isValidHost(host: String): Boolean = host.lowercase() in ALLOWED_HOSTS

        fun isValidPort(port: Int): Boolean = port in 1..65535
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

    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false)

    fun setEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENABLED, enabled).apply()
    }

    fun getHost(): String = prefs.getString(KEY_HOST, DEFAULT_HOST) ?: DEFAULT_HOST

    fun setHost(host: String) {
        if (isValidHost(host)) {
            prefs.edit().putString(KEY_HOST, host).apply()
        }
    }

    fun getPort(): Int = prefs.getInt(KEY_PORT, DEFAULT_PORT)

    fun setPort(port: Int) {
        if (isValidPort(port)) {
            prefs.edit().putInt(KEY_PORT, port).apply()
        }
    }

    fun getProxyConfig(): ProxyConfig? =
        if (isEnabled()) ProxyConfig(getHost(), getPort()) else null

    fun setProxyConfig(host: String, port: Int): Boolean {
        if (!isValidHost(host) || !isValidPort(port)) return false
        prefs.edit()
            .putString(KEY_HOST, host)
            .putInt(KEY_PORT, port)
            .apply()
        return true
    }
}

data class ProxyConfig(
    val host: String,
    val port: Int
)
