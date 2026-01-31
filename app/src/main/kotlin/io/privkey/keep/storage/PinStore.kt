package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest
import java.security.SecureRandom
import android.util.Base64

class PinStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_pin_protection"
        private const val KEY_PIN_HASH = "pin_hash"
        private const val KEY_PIN_SALT = "pin_salt"
        private const val KEY_PIN_ENABLED = "pin_enabled"
        private const val KEY_FAILED_ATTEMPTS = "failed_attempts"
        private const val KEY_LOCKOUT_UNTIL = "lockout_until"
        private const val KEY_SESSION_VALID_UNTIL = "session_valid_until"

        const val MIN_PIN_LENGTH = 4
        const val MAX_PIN_LENGTH = 8
        const val MAX_FAILED_ATTEMPTS = 5
        const val LOCKOUT_DURATION_MS = 30_000L // 30 seconds
        const val SESSION_TIMEOUT_MS = 5 * 60_000L // 5 minutes
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

    fun isPinEnabled(): Boolean = prefs.getBoolean(KEY_PIN_ENABLED, false)

    fun setPin(pin: String): Boolean {
        if (pin.length !in MIN_PIN_LENGTH..MAX_PIN_LENGTH) return false
        if (!pin.all { it.isDigit() }) return false

        val salt = generateSalt()
        val hash = hashPin(pin, salt)

        prefs.edit()
            .putString(KEY_PIN_HASH, hash)
            .putString(KEY_PIN_SALT, salt)
            .putBoolean(KEY_PIN_ENABLED, true)
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_UNTIL, 0)
            .commit()

        return true
    }

    fun verifyPin(pin: String): Boolean {
        if (isLockedOut()) return false

        val storedHash = prefs.getString(KEY_PIN_HASH, null) ?: return false
        val salt = prefs.getString(KEY_PIN_SALT, null) ?: return false

        val inputHash = hashPin(pin, salt)
        val verified = storedHash == inputHash

        if (verified) {
            clearFailedAttempts()
            refreshSession()
        } else {
            incrementFailedAttempts()
        }

        return verified
    }

    fun disablePin() {
        prefs.edit()
            .remove(KEY_PIN_HASH)
            .remove(KEY_PIN_SALT)
            .putBoolean(KEY_PIN_ENABLED, false)
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_UNTIL, 0)
            .putLong(KEY_SESSION_VALID_UNTIL, 0)
            .commit()
    }

    fun isSessionValid(): Boolean {
        if (!isPinEnabled()) return true
        val validUntil = prefs.getLong(KEY_SESSION_VALID_UNTIL, 0)
        return System.currentTimeMillis() < validUntil
    }

    fun refreshSession() {
        prefs.edit()
            .putLong(KEY_SESSION_VALID_UNTIL, System.currentTimeMillis() + SESSION_TIMEOUT_MS)
            .commit()
    }

    fun invalidateSession() {
        prefs.edit()
            .putLong(KEY_SESSION_VALID_UNTIL, 0)
            .commit()
    }

    fun isLockedOut(): Boolean {
        val lockoutUntil = prefs.getLong(KEY_LOCKOUT_UNTIL, 0)
        if (System.currentTimeMillis() >= lockoutUntil) {
            if (lockoutUntil > 0) {
                prefs.edit().putLong(KEY_LOCKOUT_UNTIL, 0).commit()
            }
            return false
        }
        return true
    }

    fun getLockoutRemainingMs(): Long {
        val lockoutUntil = prefs.getLong(KEY_LOCKOUT_UNTIL, 0)
        return maxOf(0, lockoutUntil - System.currentTimeMillis())
    }

    fun getFailedAttempts(): Int = prefs.getInt(KEY_FAILED_ATTEMPTS, 0)

    fun getRemainingAttempts(): Int = MAX_FAILED_ATTEMPTS - getFailedAttempts()

    private fun incrementFailedAttempts() {
        val attempts = getFailedAttempts() + 1
        val editor = prefs.edit().putInt(KEY_FAILED_ATTEMPTS, attempts)

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            editor.putLong(KEY_LOCKOUT_UNTIL, System.currentTimeMillis() + LOCKOUT_DURATION_MS)
            editor.putInt(KEY_FAILED_ATTEMPTS, 0)
        }

        editor.commit()
    }

    private fun clearFailedAttempts() {
        prefs.edit()
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_UNTIL, 0)
            .commit()
    }

    private fun generateSalt(): String {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        return Base64.encodeToString(salt, Base64.NO_WRAP)
    }

    private fun hashPin(pin: String, salt: String): String {
        val saltBytes = Base64.decode(salt, Base64.NO_WRAP)
        val pinBytes = pin.toByteArray(Charsets.UTF_8)
        val combined = saltBytes + pinBytes

        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(combined)
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }
}
