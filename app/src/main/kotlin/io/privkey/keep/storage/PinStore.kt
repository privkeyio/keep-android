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
        private const val KEY_LOCKOUT_SET_AT_ELAPSED = "lockout_set_at_elapsed"
        private const val KEY_LOCKOUT_WALL_CLOCK = "lockout_wall_clock"
        private const val KEY_LOCKOUT_DURATION = "lockout_duration"
        private const val KEY_SESSION_TIMEOUT = "session_timeout"

        const val MIN_PIN_LENGTH = 4
        const val MAX_PIN_LENGTH = 8
        const val MAX_FAILED_ATTEMPTS = 5
        const val DEFAULT_SESSION_TIMEOUT_MS = 300_000L
        val SESSION_TIMEOUT_OPTIONS_MS = longArrayOf(0L, 60_000L, 300_000L, 600_000L)
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
            "00000", "11111", "000000", "111111", "0000000", "1111111", "00000000", "11111111"
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

    @Synchronized
    fun isPinEnabled(): Boolean = prefs.getBoolean(KEY_PIN_ENABLED, false)

    @Synchronized
    fun requiresAuthentication(): Boolean = isPinEnabled() && !isSessionValid()

    @Synchronized
    fun isWeakPin(pin: String): Boolean {
        // Non-digit PINs are treated as weak/invalid to avoid digitToInt() exceptions
        if (!pin.all { it.isDigit() }) return true
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

    @Synchronized
    fun setPin(pin: String): Boolean {
        if (pin.length !in MIN_PIN_LENGTH..MAX_PIN_LENGTH) return false
        if (!pin.all { it.isDigit() }) return false
        if (isWeakPin(pin)) return false

        val pinChars = pin.toCharArray()
        try {
            val salt = generateSalt()
            val hash = hashPinFromChars(pinChars, salt)

            val success = prefs.edit()
                .putString(KEY_PIN_HASH, hash)
                .putString(KEY_PIN_SALT, salt)
                .putBoolean(KEY_PIN_ENABLED, true)
                .putInt(KEY_FAILED_ATTEMPTS, 0)
                .putLong(KEY_LOCKOUT_UNTIL, 0)
                .putInt(KEY_LOCKOUT_LEVEL, 0)
                .putLong(KEY_LOCKOUT_SET_AT_ELAPSED, 0)
                .putLong(KEY_LOCKOUT_WALL_CLOCK, 0)
                .putLong(KEY_LOCKOUT_DURATION, 0)
                .commit()
            if (success) refreshSession()
            return success
        } finally {
            pinChars.fill('0')
        }
    }

    @Synchronized
    fun verifyPin(pin: String): Boolean {
        if (isLockedOut()) return false

        val storedHash = prefs.getString(KEY_PIN_HASH, null) ?: return false
        val salt = prefs.getString(KEY_PIN_SALT, null) ?: return false

        val pinChars = pin.toCharArray()
        try {
            val inputHash = hashPinFromChars(pinChars, salt)
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
        } finally {
            pinChars.fill('0')
        }
    }

    @Synchronized
    fun disablePin(currentPin: String): Boolean {
        if (!verifyPin(currentPin)) return false
        return prefs.edit()
            .remove(KEY_PIN_HASH)
            .remove(KEY_PIN_SALT)
            .putBoolean(KEY_PIN_ENABLED, false)
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_UNTIL, 0)
            .putLong(KEY_SESSION_VALID_UNTIL, 0)
            .putLong(KEY_SESSION_STARTED_AT_REALTIME, 0)
            .putInt(KEY_LOCKOUT_LEVEL, 0)
            .putLong(KEY_LOCKOUT_SET_AT_ELAPSED, 0)
            .putLong(KEY_LOCKOUT_WALL_CLOCK, 0)
            .putLong(KEY_LOCKOUT_DURATION, 0)
            .commit()
    }

    @Synchronized
    fun isSessionValid(): Boolean {
        if (!isPinEnabled()) return true
        val sessionStartedAt = prefs.getLong(KEY_SESSION_STARTED_AT_REALTIME, 0)
        if (sessionStartedAt == 0L) return false
        val timeout = getSessionTimeout()
        if (timeout == 0L) return false
        val elapsed = SystemClock.elapsedRealtime() - sessionStartedAt
        return elapsed in 0..timeout
    }

    @Synchronized
    fun getSessionTimeout(): Long = prefs.getLong(KEY_SESSION_TIMEOUT, DEFAULT_SESSION_TIMEOUT_MS)

    @Synchronized
    fun setSessionTimeout(timeoutMs: Long): Boolean {
        if (timeoutMs !in SESSION_TIMEOUT_OPTIONS_MS) return false
        return prefs.edit().putLong(KEY_SESSION_TIMEOUT, timeoutMs).commit()
    }

    @Synchronized
    fun refreshSession() {
        prefs.edit()
            .putLong(KEY_SESSION_STARTED_AT_REALTIME, SystemClock.elapsedRealtime())
            .commit()
    }

    @Synchronized
    fun invalidateSession() {
        prefs.edit()
            .putLong(KEY_SESSION_STARTED_AT_REALTIME, 0)
            .commit()
    }

    @Synchronized
    fun isLockedOut(): Boolean = getLockoutRemainingMs() > 0

    @Synchronized
    fun getLockoutRemainingMs(): Long {
        val lockoutWallClock = prefs.getLong(KEY_LOCKOUT_WALL_CLOCK, 0)
        val lockoutDuration = prefs.getLong(KEY_LOCKOUT_DURATION, 0)
        val lockoutUntil = prefs.getLong(KEY_LOCKOUT_UNTIL, 0)
        val savedSetElapsed = prefs.getLong(KEY_LOCKOUT_SET_AT_ELAPSED, 0)
        val currentElapsed = SystemClock.elapsedRealtime()

        val remainingWallClock = if (lockoutWallClock != 0L && lockoutDuration != 0L) {
            lockoutWallClock + lockoutDuration - System.currentTimeMillis()
        } else 0L

        val remainingElapsed = if (lockoutUntil != 0L && savedSetElapsed != 0L && currentElapsed >= savedSetElapsed) {
            lockoutUntil - currentElapsed
        } else 0L

        val remaining = maxOf(remainingWallClock, remainingElapsed)
        if (remaining <= 0) {
            clearLockoutTimestamps()
            return 0
        }
        return remaining
    }

    private fun clearLockoutTimestamps() {
        prefs.edit()
            .putLong(KEY_LOCKOUT_UNTIL, 0)
            .putLong(KEY_LOCKOUT_SET_AT_ELAPSED, 0)
            .putLong(KEY_LOCKOUT_WALL_CLOCK, 0)
            .putLong(KEY_LOCKOUT_DURATION, 0)
            .commit()
    }

    @Synchronized
    fun getFailedAttempts(): Int = prefs.getInt(KEY_FAILED_ATTEMPTS, 0)

    @Synchronized
    fun getRemainingAttempts(): Int = MAX_FAILED_ATTEMPTS - getFailedAttempts()

    private fun incrementFailedAttempts() {
        val attempts = getFailedAttempts() + 1
        val editor = prefs.edit().putInt(KEY_FAILED_ATTEMPTS, attempts)

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            val currentLevel = prefs.getInt(KEY_LOCKOUT_LEVEL, 0)
            val duration = LOCKOUT_DURATIONS_MS[currentLevel.coerceIn(0, LOCKOUT_DURATIONS_MS.size - 1)]
            val newLevel = (currentLevel + 1).coerceAtMost(LOCKOUT_DURATIONS_MS.size - 1)
            val currentElapsed = SystemClock.elapsedRealtime()
            val currentWallClock = System.currentTimeMillis()
            editor.putLong(KEY_LOCKOUT_UNTIL, currentElapsed + duration)
            editor.putLong(KEY_LOCKOUT_SET_AT_ELAPSED, currentElapsed)
            editor.putLong(KEY_LOCKOUT_WALL_CLOCK, currentWallClock)
            editor.putLong(KEY_LOCKOUT_DURATION, duration)
            editor.putInt(KEY_FAILED_ATTEMPTS, 0)
            editor.putInt(KEY_LOCKOUT_LEVEL, newLevel)
        }

        editor.commit()
    }

    private fun clearFailedAttempts() {
        clearLockoutTimestamps()
        prefs.edit()
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putInt(KEY_LOCKOUT_LEVEL, 0)
            .commit()
    }

    private fun generateSalt(): String {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        return Base64.encodeToString(salt, Base64.NO_WRAP)
    }

    private fun hashPinFromChars(pinChars: CharArray, salt: String): String {
        val saltBytes = Base64.decode(salt, Base64.NO_WRAP)
        val spec = PBEKeySpec(pinChars, saltBytes, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH)
        try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val hash = factory.generateSecret(spec).encoded
            return Base64.encodeToString(hash, Base64.NO_WRAP)
        } finally {
            spec.clearPassword()
        }
    }
}
