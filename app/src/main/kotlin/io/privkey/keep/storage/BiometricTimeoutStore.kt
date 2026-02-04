package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import android.os.SystemClock
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class BiometricTimeoutStore(context: Context) {
    companion object {
        private const val PREFS_NAME = "keep_biometric_timeout"
        private const val KEY_TIMEOUT = "biometric_timeout"
        private const val KEY_LAST_AUTH_REALTIME = "last_auth_realtime"
        private const val KEY_LAST_AUTH_WALL = "last_auth_wall"

        const val TIMEOUT_EVERY_TIME = 0L
        const val TIMEOUT_1_MINUTE = 60_000L
        const val TIMEOUT_5_MINUTES = 300_000L
        const val TIMEOUT_10_MINUTES = 600_000L

        val TIMEOUT_OPTIONS = longArrayOf(
            TIMEOUT_EVERY_TIME,
            TIMEOUT_1_MINUTE,
            TIMEOUT_5_MINUTES,
            TIMEOUT_10_MINUTES
        )

        fun formatTimeout(timeoutMs: Long): String =
            when (timeoutMs) {
                TIMEOUT_EVERY_TIME -> "Every time"
                TIMEOUT_1_MINUTE -> "1 minute"
                TIMEOUT_5_MINUTES -> "5 minutes"
                TIMEOUT_10_MINUTES -> "10 minutes"
                else -> "Unknown"
            }
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

    @Synchronized
    fun getTimeout(): Long = prefs.getLong(KEY_TIMEOUT, TIMEOUT_EVERY_TIME)

    @Synchronized
    fun setTimeout(timeoutMs: Long): Boolean {
        if (timeoutMs !in TIMEOUT_OPTIONS) return false
        prefs.edit().putLong(KEY_TIMEOUT, timeoutMs).apply()
        return true
    }

    @Synchronized
    fun recordAuthentication() {
        prefs
            .edit()
            .putLong(KEY_LAST_AUTH_REALTIME, SystemClock.elapsedRealtime())
            .putLong(KEY_LAST_AUTH_WALL, System.currentTimeMillis())
            .apply()
    }

    @Synchronized
    fun invalidateSession() {
        prefs
            .edit()
            .putLong(KEY_LAST_AUTH_REALTIME, 0L)
            .putLong(KEY_LAST_AUTH_WALL, 0L)
            .apply()
    }
}
