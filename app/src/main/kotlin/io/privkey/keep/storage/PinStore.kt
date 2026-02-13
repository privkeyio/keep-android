package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import io.privkey.keep.BuildConfig
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class PinStore(private val context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_pin_protection"
        private const val KEY_PIN_HASH = "pin_hash"
        private const val KEY_PIN_SALT = "pin_salt"
        private const val KEY_PIN_ENABLED = "pin_enabled"
        private const val KEY_FAILED_ATTEMPTS = "failed_attempts"
        private const val KEY_SESSION_STARTED_AT_REALTIME = "session_started_at_realtime"
        private const val KEY_SESSION_STARTED_AT_WALL = "session_started_at_wall"
        private const val KEY_SESSION_TIMEOUT = "session_timeout"
        private const val KEY_LOCKOUT_LEVEL = "lockout_level"
        private const val KEY_LOCKOUT_SET_AT_ELAPSED = "lockout_set_at_elapsed"
        private const val KEY_LOCKOUT_WALL_CLOCK = "lockout_wall_clock"
        private const val KEY_LOCKOUT_DURATION = "lockout_duration"
        private const val KEY_LAST_LOCKOUT_CLEARED = "last_lockout_cleared"

        const val MIN_PIN_LENGTH = 4
        const val MAX_PIN_LENGTH = 16
        private const val OLD_MAX_PIN_LENGTH = 8
        const val MAX_FAILED_ATTEMPTS = 5
        const val DEFAULT_SESSION_TIMEOUT_MS = 300_000L
        val SESSION_TIMEOUT_OPTIONS_MS = longArrayOf(0L, 60_000L, 300_000L, 600_000L)
        private const val PBKDF2_ITERATIONS = 120_000
        private const val PBKDF2_KEY_LENGTH = 256

        private const val DUMMY_SALT = "AAAAAAAAAAAAAAAAAAAAAA=="
        private const val DUMMY_HASH = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

        private val LOCKOUT_DURATIONS_MS = longArrayOf(
            30_000L,     // 30 seconds
            60_000L,     // 1 minute
            300_000L,    // 5 minutes
            900_000L,    // 15 minutes
            3600_000L    // 1 hour
        )

        private const val LOCKOUT_LEVEL_DECAY_MS = 86_400_000L  // 24 hours

        private val WEAK_PINS = setOf(
            "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
            "1234", "4321", "1212", "2121", "0123", "3210", "9876", "6789",
            "12345", "54321", "123456", "654321", "1234567", "7654321", "12345678", "87654321",
            "00000", "11111", "000000", "111111", "0000000", "1111111", "00000000", "11111111",
            "123456789", "1234567890", "9876543210"
        )
    }

    private val prefs: SharedPreferences = run {
        val newPrefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        LegacyPrefsMigration.migrateIfNeeded(context, PREFS_NAME, newPrefs)
    }

    @Synchronized
    fun isPinEnabled(): Boolean = prefs.getBoolean(KEY_PIN_ENABLED, false)

    @Synchronized
    fun requiresAuthentication(): Boolean = isPinEnabled() && !isSessionValid()

    @Synchronized
    fun isWeakPin(pin: String): Boolean {
        if (!pin.all { it.isDigit() }) return true
        if (pin in WEAK_PINS) return true
        if (pin.length < 3) return false
        if (pin.all { it == pin[0] }) return true

        val digits = pin.map { it.digitToInt() }
        return digits.zipWithNext().all { (a, b) -> b == a + 1 } ||
            digits.zipWithNext().all { (a, b) -> b == a - 1 }
    }

    @Synchronized
    fun setPin(pin: String): Boolean {
        if (pin.length !in MIN_PIN_LENGTH..MAX_PIN_LENGTH) return false
        if (!pin.all { it.isDigit() }) return false
        if (isWeakPin(pin)) return false

        val normalizedPin = CharArray(MAX_PIN_LENGTH) { i -> if (i < pin.length) pin[i] else '\u0000' }
        try {
            val salt = generateSalt()
            val hash = hashPinFromChars(normalizedPin, salt)

            val success = prefs.edit()
                .putString(KEY_PIN_HASH, hash)
                .putString(KEY_PIN_SALT, salt)
                .putBoolean(KEY_PIN_ENABLED, true)
                .putInt(KEY_FAILED_ATTEMPTS, 0)
                .putInt(KEY_LOCKOUT_LEVEL, 0)
                .putLong(KEY_LOCKOUT_SET_AT_ELAPSED, 0)
                .putLong(KEY_LOCKOUT_WALL_CLOCK, 0)
                .putLong(KEY_LOCKOUT_DURATION, 0)
                .putLong(KEY_LAST_LOCKOUT_CLEARED, 0)
                .commit()
            if (success) refreshSession()
            return success
        } finally {
            normalizedPin.fill('\u0000')
        }
    }

    @Synchronized
    fun verifyPin(pin: String): Boolean {
        if (pin.length < MIN_PIN_LENGTH) return false
        val invalidLength = pin.length > MAX_PIN_LENGTH
        val lockedOut = isLockedOut()

        val storedHash = prefs.getString(KEY_PIN_HASH, null)
        val salt = prefs.getString(KEY_PIN_SALT, null)

        val pinNotSet = storedHash == null || salt == null
        val effectiveSalt = salt ?: DUMMY_SALT
        val effectiveStoredHash = storedHash ?: DUMMY_HASH

        val normalizedPin = CharArray(MAX_PIN_LENGTH) { i -> if (i < pin.length) pin[i] else '\u0000' }
        val oldNormalizedPin = CharArray(OLD_MAX_PIN_LENGTH) { i -> if (i < pin.length) pin[i] else '\u0000' }
        val legacyPin = pin.toCharArray()
        try {
            val storedBytes = Base64.decode(effectiveStoredHash, Base64.NO_WRAP)

            val normalizedHash = hashPinFromChars(normalizedPin, effectiveSalt)
            val normalizedBytes = Base64.decode(normalizedHash, Base64.NO_WRAP)
            var hashesMatch = MessageDigest.isEqual(storedBytes, normalizedBytes)

            if (!hashesMatch && !pinNotSet && !invalidLength && !lockedOut) {
                val oldNormalizedHash = hashPinFromChars(oldNormalizedPin, effectiveSalt)
                val oldNormalizedBytes = Base64.decode(oldNormalizedHash, Base64.NO_WRAP)
                if (MessageDigest.isEqual(storedBytes, oldNormalizedBytes)) {
                    hashesMatch = true
                    if (!prefs.edit().putString(KEY_PIN_HASH, normalizedHash).commit()) {
                        if (BuildConfig.DEBUG) Log.w("PinStore", "Failed to persist migrated PIN hash")
                    }
                }
            }

            if (!hashesMatch && !pinNotSet && !invalidLength && !lockedOut) {
                val legacyHash = hashPinFromChars(legacyPin, effectiveSalt)
                val legacyBytes = Base64.decode(legacyHash, Base64.NO_WRAP)
                val legacyMatch = MessageDigest.isEqual(storedBytes, legacyBytes)
                if (legacyMatch) {
                    hashesMatch = true
                    if (!prefs.edit().putString(KEY_PIN_HASH, normalizedHash).commit()) {
                        if (BuildConfig.DEBUG) Log.w("PinStore", "Failed to persist migrated PIN hash")
                    }
                }
            }

            val verified = hashesMatch && !invalidLength && !lockedOut && !pinNotSet

            if (verified) {
                clearFailedAttempts()
                refreshSession()
            } else if (!lockedOut && !pinNotSet && !invalidLength) {
                incrementFailedAttempts()
            }

            return verified
        } finally {
            normalizedPin.fill('\u0000')
            oldNormalizedPin.fill('\u0000')
            legacyPin.fill('\u0000')
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
            .putInt(KEY_LOCKOUT_LEVEL, 0)
            .putLong(KEY_SESSION_STARTED_AT_REALTIME, 0)
            .putLong(KEY_SESSION_STARTED_AT_WALL, 0)
            .putLong(KEY_LOCKOUT_SET_AT_ELAPSED, 0)
            .putLong(KEY_LOCKOUT_WALL_CLOCK, 0)
            .putLong(KEY_LOCKOUT_DURATION, 0)
            .putLong(KEY_LAST_LOCKOUT_CLEARED, 0)
            .commit()
    }

    @Synchronized
    fun isSessionValid(): Boolean {
        if (!isPinEnabled()) return true
        val sessionStartedAtRealtime = prefs.getLong(KEY_SESSION_STARTED_AT_REALTIME, 0)
        val sessionStartedAtWall = prefs.getLong(KEY_SESSION_STARTED_AT_WALL, 0)
        if (sessionStartedAtRealtime == 0L || sessionStartedAtWall == 0L) return false
        val timeout = getSessionTimeout()
        if (timeout == 0L) return false
        val currentRealtime = SystemClock.elapsedRealtime()
        val currentWall = System.currentTimeMillis()
        val rebootDetected = currentRealtime < sessionStartedAtRealtime
        if (rebootDetected) {
            invalidateSession()
            return false
        }
        val elapsedRealtime = currentRealtime - sessionStartedAtRealtime
        val elapsedWall = currentWall - sessionStartedAtWall
        if (elapsedWall < 0) {
            invalidateSession()
            return false
        }
        return elapsedRealtime in 0..timeout && elapsedWall in 0..timeout
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
            .putLong(KEY_SESSION_STARTED_AT_WALL, System.currentTimeMillis())
            .commit()
    }

    @Synchronized
    fun invalidateSession() {
        prefs.edit()
            .putLong(KEY_SESSION_STARTED_AT_REALTIME, 0)
            .putLong(KEY_SESSION_STARTED_AT_WALL, 0)
            .commit()
    }

    @Synchronized
    fun isLockedOut(): Boolean = getLockoutRemainingMs() > 0

    @Synchronized
    fun getLockoutRemainingMs(): Long {
        val lockoutDuration = prefs.getLong(KEY_LOCKOUT_DURATION, 0)
        if (lockoutDuration == 0L) {
            maybeDecayLockoutLevel()
            return 0
        }

        val savedSetElapsed = prefs.getLong(KEY_LOCKOUT_SET_AT_ELAPSED, 0)
        val currentElapsed = SystemClock.elapsedRealtime()

        val rebootDetected = currentElapsed < savedSetElapsed
        if (rebootDetected) {
            val lockoutWallClock = prefs.getLong(KEY_LOCKOUT_WALL_CLOCK, 0)
            if (lockoutWallClock == 0L) {
                clearLockoutTimestampsInternal()
                return 0
            }
            val currentWallClock = System.currentTimeMillis()
            val remainingByWallClock = (lockoutWallClock + lockoutDuration) - currentWallClock
            if (remainingByWallClock <= 0) {
                clearLockoutTimestampsInternal()
                return 0
            }
            return remainingByWallClock
        }

        val remainingByElapsed = lockoutDuration - (currentElapsed - savedSetElapsed)
        if (remainingByElapsed <= 0) {
            clearLockoutTimestampsInternal()
            return 0
        }
        return remainingByElapsed
    }

    private fun maybeDecayLockoutLevel() {
        val currentLevel = prefs.getInt(KEY_LOCKOUT_LEVEL, 0)
        if (currentLevel == 0) return

        val lastCleared = prefs.getLong(KEY_LAST_LOCKOUT_CLEARED, 0)
        if (lastCleared == 0L) return

        val now = System.currentTimeMillis()
        val elapsed = now - lastCleared
        if (elapsed < 0) {
            prefs.edit().putLong(KEY_LAST_LOCKOUT_CLEARED, now).commit()
            return
        }

        val decaySteps = (elapsed / LOCKOUT_LEVEL_DECAY_MS).toInt()
        if (decaySteps == 0) return

        val newLevel = (currentLevel - decaySteps).coerceAtLeast(0)
        val newLastCleared = lastCleared + decaySteps * LOCKOUT_LEVEL_DECAY_MS
        prefs.edit()
            .putInt(KEY_LOCKOUT_LEVEL, newLevel)
            .putLong(KEY_LAST_LOCKOUT_CLEARED, newLastCleared)
            .commit()
    }

    private fun clearLockoutTimestampsInternal() {
        prefs.edit()
            .putLong(KEY_LOCKOUT_SET_AT_ELAPSED, 0)
            .putLong(KEY_LOCKOUT_WALL_CLOCK, 0)
            .putLong(KEY_LOCKOUT_DURATION, 0)
            .putLong(KEY_LAST_LOCKOUT_CLEARED, System.currentTimeMillis())
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
            editor.putLong(KEY_LOCKOUT_SET_AT_ELAPSED, SystemClock.elapsedRealtime())
            editor.putLong(KEY_LOCKOUT_WALL_CLOCK, System.currentTimeMillis())
            editor.putLong(KEY_LOCKOUT_DURATION, duration)
            editor.putInt(KEY_FAILED_ATTEMPTS, 0)
            editor.putInt(KEY_LOCKOUT_LEVEL, newLevel)
        }

        if (!editor.commit()) {
            if (BuildConfig.DEBUG) Log.e("PinStore", "Failed to persist lockout state")
        }
    }

    private fun clearFailedAttempts() {
        val currentLevel = prefs.getInt(KEY_LOCKOUT_LEVEL, 0)
        val editor = prefs.edit()
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_SET_AT_ELAPSED, 0)
            .putLong(KEY_LOCKOUT_WALL_CLOCK, 0)
            .putLong(KEY_LOCKOUT_DURATION, 0)
        if (currentLevel > 0) {
            editor.putLong(KEY_LAST_LOCKOUT_CLEARED, System.currentTimeMillis())
        }
        editor.commit()
    }

    private fun generateSalt(): String {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        return Base64.encodeToString(salt, Base64.NO_WRAP)
    }

    private fun hashPinFromChars(pinChars: CharArray, salt: String): String {
        require(salt.isNotBlank()) { "Salt must not be blank" }
        require(pinChars.isNotEmpty()) { "PIN chars must not be empty" }
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
