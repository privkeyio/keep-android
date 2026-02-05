package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences

class ProxyConfigStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_proxy_config"
        private const val KEY_ENABLED = "proxy_enabled"
        private const val KEY_HOST = "proxy_host"
        private const val KEY_PORT = "proxy_port"
        private const val DEFAULT_HOST = "127.0.0.1"
        private const val DEFAULT_PORT = 9050
        private val ALLOWED_HOSTS = setOf("127.0.0.1", "localhost", "::1", "[::1]")
        private const val MIN_PORT = 1
        private const val MAX_PORT = 65535

        fun isValidHost(host: String): Boolean = host.lowercase() in ALLOWED_HOSTS

        fun isValidPort(port: Int): Boolean = port in MIN_PORT..MAX_PORT
    }

    private val prefs: SharedPreferences = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false)

    fun setEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENABLED, enabled).commit()
    }

    fun getHost(): String = prefs.getString(KEY_HOST, DEFAULT_HOST) ?: DEFAULT_HOST

    fun setHost(host: String) {
        if (isValidHost(host)) {
            prefs.edit().putString(KEY_HOST, host).commit()
        }
    }

    fun getPort(): Int = prefs.getInt(KEY_PORT, DEFAULT_PORT)

    fun setPort(port: Int) {
        if (isValidPort(port)) {
            prefs.edit().putInt(KEY_PORT, port).commit()
        }
    }

    fun getProxyConfig(): ProxyConfig? {
        if (!isEnabled()) return null
        val host = getHost()
        val port = getPort()
        if (!isValidHost(host) || !isValidPort(port)) return null
        return ProxyConfig(host, port)
    }

    fun setProxyConfig(host: String, port: Int): Boolean {
        if (!isValidHost(host) || !isValidPort(port)) return false
        prefs.edit()
            .putString(KEY_HOST, host)
            .putInt(KEY_PORT, port)
            .commit()
        return true
    }
}

data class ProxyConfig(
    val host: String,
    val port: Int
)
