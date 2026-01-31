package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import android.os.SystemClock
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest
import java.security.SecureRandom
import android.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class PinStore(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_pin_protection"
        private const val KEY_PIN_HASH = "pin_hash"
        private const val KEY_PIN_SALT = "pin_salt"
        private const val KEY_PIN_ENABLED = "pin_enabled"
        private const val KEY_FAILED_ATTEMPTS = "failed_attempts"
        private const val KEY_LOCKOUT_UNTIL = "lockout_until"
        private const val KEY_SESSION_VALID_UNTIL = "session_valid_until"
        private const val KEY_SESSION_STARTED_AT_REALTIME = "session_started_at_realtime"
        private const val KEY_LOCKOUT_LEVEL = "lockout_level"

        const val MIN_PIN_LENGTH = 4
        const val MAX_PIN_LENGTH = 8
        const val MAX_FAILED_ATTEMPTS = 5
        const val SESSION_TIMEOUT_MS = 5 * 60_000L // 5 minutes
        private const val PBKDF2_ITERATIONS = 120_000
        private const val PBKDF2_KEY_LENGTH = 256

        private val LOCKOUT_DURATIONS_MS = longArrayOf(
            30_000L,     // 30 seconds
            60_000L,     // 1 minute
            300_000L,    // 5 minutes
            900_000L,    // 15 minutes
            3600_000L    // 1 hour
        )

        private val WEAK_PINS = setOf(
            "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
            "1234", "4321", "1212", "2121", "0123", "3210", "9876", "6789",
            "12345", "54321", "123456", "654321", "1234567", "7654321", "12345678", "87654321",
            "00000", "11111", "00000000", "11111111",
            "0000000", "1111111", "00000000", "11111111"
        )
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

    fun isWeakPin(pin: String): Boolean {
        if (WEAK_PINS.contains(pin)) return true
        if (pin.length >= 3 && pin.all { it == pin[0] }) return true
        val digits = pin.map { it.digitToInt() }
        if (digits.size >= 3) {
            val isAscending = digits.zipWithNext().all { (a, b) -> b == a + 1 }
            val isDescending = digits.zipWithNext().all { (a, b) -> b == a - 1 }
            if (isAscending || isDescending) return true
        }
        return false
    }

    fun setPin(pin: String): Boolean {
        if (pin.length !in MIN_PIN_LENGTH..MAX_PIN_LENGTH) return false
        if (!pin.all { it.isDigit() }) return false
        if (isWeakPin(pin)) return false

        val salt = generateSalt()
        val hash = hashPin(pin, salt)

        prefs.edit()
            .putString(KEY_PIN_HASH, hash)
            .putString(KEY_PIN_SALT, salt)
            .putBoolean(KEY_PIN_ENABLED, true)
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_UNTIL, 0)
            .putInt(KEY_LOCKOUT_LEVEL, 0)
            .commit()

        return true
    }

    fun verifyPin(pin: String): Boolean {
        if (isLockedOut()) return false

        val storedHash = prefs.getString(KEY_PIN_HASH, null) ?: return false
        val salt = prefs.getString(KEY_PIN_SALT, null) ?: return false

        val inputHash = hashPin(pin, salt)
        val storedBytes = Base64.decode(storedHash, Base64.NO_WRAP)
        val inputBytes = Base64.decode(inputHash, Base64.NO_WRAP)
        val verified = MessageDigest.isEqual(storedBytes, inputBytes)

        if (verified) {
            clearFailedAttempts()
            refreshSession()
        } else {
            incrementFailedAttempts()
        }

        return verified
    }

    fun disablePin(currentPin: String): Boolean {
        if (!verifyPin(currentPin)) return false
        prefs.edit()
            .remove(KEY_PIN_HASH)
            .remove(KEY_PIN_SALT)
            .putBoolean(KEY_PIN_ENABLED, false)
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_UNTIL, 0)
            .putLong(KEY_SESSION_VALID_UNTIL, 0)
            .putLong(KEY_SESSION_STARTED_AT_REALTIME, 0)
            .putInt(KEY_LOCKOUT_LEVEL, 0)
            .commit()
        return true
    }

    fun isSessionValid(): Boolean {
        if (!isPinEnabled()) return true
        val sessionStartedAt = prefs.getLong(KEY_SESSION_STARTED_AT_REALTIME, 0)
        if (sessionStartedAt == 0L) return false
        val elapsed = SystemClock.elapsedRealtime() - sessionStartedAt
        return elapsed in 0..SESSION_TIMEOUT_MS
    }

    fun refreshSession() {
        prefs.edit()
            .putLong(KEY_SESSION_STARTED_AT_REALTIME, SystemClock.elapsedRealtime())
            .commit()
    }

    fun invalidateSession() {
        prefs.edit()
            .putLong(KEY_SESSION_STARTED_AT_REALTIME, 0)
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
            val currentLevel = prefs.getInt(KEY_LOCKOUT_LEVEL, 0)
            val lockoutDuration = LOCKOUT_DURATIONS_MS[currentLevel.coerceIn(0, LOCKOUT_DURATIONS_MS.size - 1)]
            val newLevel = (currentLevel + 1).coerceAtMost(LOCKOUT_DURATIONS_MS.size - 1)
            editor.putLong(KEY_LOCKOUT_UNTIL, System.currentTimeMillis() + lockoutDuration)
            editor.putInt(KEY_FAILED_ATTEMPTS, 0)
            editor.putInt(KEY_LOCKOUT_LEVEL, newLevel)
        }

        editor.commit()
    }

    private fun clearFailedAttempts() {
        prefs.edit()
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_UNTIL, 0)
            .putInt(KEY_LOCKOUT_LEVEL, 0)
            .commit()
    }

    private fun generateSalt(): String {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        return Base64.encodeToString(salt, Base64.NO_WRAP)
    }

    private fun hashPin(pin: String, salt: String): String {
        val saltBytes = Base64.decode(salt, Base64.NO_WRAP)
        val spec = PBEKeySpec(pin.toCharArray(), saltBytes, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val hash = factory.generateSecret(spec).encoded
        spec.clearPassword()
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }
}
