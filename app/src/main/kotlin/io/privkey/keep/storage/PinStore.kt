package io.privkey.keep.storage

import android.content.Context
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import io.privkey.keep.BuildConfig
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * What the stored record can say about whether a PIN is set.
 *
 * Three-way for the same reason [PrefRead] is: this record carries a restriction, and
 * the ordinary getters answer the caller's default for both "nothing is stored" and
 * "something is stored and will not decrypt", which are opposite facts here. The first
 * means no PIN gate; the second means a PIN may be set and cannot be verified.
 */
enum class PinRecord { NOT_SET, SET, UNREADABLE }

class PinStore(private val context: Context) {

    companion object {
        /**
         * Not private: the tests that stage an unreadable PIN record have to reach the
         * real file, and a copy of the literal there would silently stop matching if
         * this one changed.
         */
        internal const val PREFS_NAME = "keep_pin_protection"
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
        private const val KEY_LOCKOUT_EPOCH = "lockout_epoch"
        private const val KEY_BIOMETRIC_RESET_REQUIRED = "biometric_reset_required"

        const val MIN_PIN_LENGTH = 4
        const val MAX_PIN_LENGTH = 16
        private const val OLD_MAX_PIN_LENGTH = 8
        const val MAX_FAILED_ATTEMPTS = 5
        const val DEFAULT_SESSION_TIMEOUT_MS = 300_000L
        val SESSION_TIMEOUT_OPTIONS_MS = longArrayOf(0L, 60_000L, 300_000L, 600_000L)
        private const val PBKDF2_ITERATIONS = 120_000
        private const val PBKDF2_KEY_LENGTH = 256
        private const val LOCKOUT_EPOCHS_BEFORE_BIOMETRIC = 3

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

    private val prefs: ReadablePrefs = run {
        val newPrefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        LegacyPrefsMigration.migrateIfNeeded(context, PREFS_NAME, newPrefs)
    }

    /**
     * Every read below goes through [PrefRead] and resolves an unreadable value to the
     * answer that keeps a restriction in force, never the one that lifts it. This file
     * holds the PIN gate, the lockout, the attempt counter and the biometric-reset
     * requirement, and all four are restrictions, so the collapsing getters turned a
     * record that would not decrypt into no PIN, no lockout, no attempts used and no
     * reset owed. The gates at MainActivity, Nip55Activity and Nip55ContentProvider all
     * ask through [requiresAuthentication], so that answer stopped every one of them
     * asking.
     *
     * Failing closed on its own would lock the person out of the app, since the hash in
     * the same file is equally unreadable and no PIN can then verify, which is why
     * [clearPin] exists and why the unlock screen offers it.
     */
    @Synchronized
    fun pinRecord(): PinRecord = when (val read = prefs.readBoolean(KEY_PIN_ENABLED)) {
        is PrefRead.Found -> if (read.value) PinRecord.SET else PinRecord.NOT_SET
        PrefRead.Absent -> PinRecord.NOT_SET
        PrefRead.Unreadable -> PinRecord.UNREADABLE
    }

    /** True when a PIN may be set, which includes a record that cannot be read. */
    @Synchronized
    fun isPinEnabled(): Boolean = pinRecord() != PinRecord.NOT_SET

    /**
     * Deletes the whole PIN record, the way back from a record that cannot be read.
     *
     * Refuses unless the record is actually unreadable, so this cannot become a way to
     * remove a working PIN without verifying it. That is a check rather than a comment
     * because the call is reachable from the unlock screen, which is the one screen
     * shown to someone who has not authenticated yet.
     *
     * Clears the file rather than the keys, which is what works when the fault is the
     * file's own HMAC key: resolving a name to remove it decrypts that key, so a
     * targeted remove raises instead of answering, while a clear resolves no names and
     * takes the damaged key material with it.
     */
    @Synchronized
    fun clearPin(): Boolean {
        if (pinRecord() != PinRecord.UNREADABLE) return false
        return runCatching { prefs.edit().clear().commit() }.getOrDefault(false)
    }

    @Synchronized
    fun requiresAuthentication(): Boolean = isPinEnabled() && !isSessionValid()

    // Both answers are named at every call site below. The bug these replace was that
    // the getters gave one answer for both, and for roughly half of this file's keys
    // the absent answer is the permissive one.
    private fun longAt(key: String, ifAbsent: Long, ifUnreadable: Long): Long =
        when (val read = prefs.readLong(key)) {
            is PrefRead.Found -> read.value
            PrefRead.Absent -> ifAbsent
            PrefRead.Unreadable -> ifUnreadable
        }

    private fun intAt(key: String, ifAbsent: Int, ifUnreadable: Int): Int =
        when (val read = prefs.readInt(key)) {
            is PrefRead.Found -> read.value
            PrefRead.Absent -> ifAbsent
            PrefRead.Unreadable -> ifUnreadable
        }

    private fun boolAt(key: String, ifAbsent: Boolean, ifUnreadable: Boolean): Boolean =
        when (val read = prefs.readBoolean(key)) {
            is PrefRead.Found -> read.value
            PrefRead.Absent -> ifAbsent
            PrefRead.Unreadable -> ifUnreadable
        }

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
                .putInt(KEY_LOCKOUT_EPOCH, 0)
                .putBoolean(KEY_BIOMETRIC_RESET_REQUIRED, false)
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

        // A record that will not decrypt cannot verify anything, and must not spend the
        // attempt budget on a fault that is not a wrong PIN: burning attempts here would
        // drive the lockout for a record no PIN can ever satisfy. The constant-time dance
        // below is kept for the readable path, where a timing difference would separate
        // "no PIN set" from "wrong PIN"; this state is already named on screen, so there
        // is nothing for it to leak.
        val hashRead = prefs.readString(KEY_PIN_HASH)
        val saltRead = prefs.readString(KEY_PIN_SALT)
        if (hashRead == PrefRead.Unreadable || saltRead == PrefRead.Unreadable) return false

        val storedHash = (hashRead as? PrefRead.Found)?.value
        val salt = (saltRead as? PrefRead.Found)?.value

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
                clearFailedAttemptsAndResetEpoch()
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
            .putInt(KEY_LOCKOUT_EPOCH, 0)
            .putBoolean(KEY_BIOMETRIC_RESET_REQUIRED, false)
            .commit()
    }

    @Synchronized
    fun isSessionValid(): Boolean {
        if (!isPinEnabled()) return true
        // An unreadable timestamp answers 0, which is the no-session value, so an
        // unreadable session is not a valid one.
        val sessionStartedAtRealtime = longAt(KEY_SESSION_STARTED_AT_REALTIME, ifAbsent = 0, ifUnreadable = 0)
        val sessionStartedAtWall = longAt(KEY_SESSION_STARTED_AT_WALL, ifAbsent = 0, ifUnreadable = 0)
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
    // 0 is a configured option here, meaning authenticate every time, so it is the
    // strictest answer available rather than an invented one. An unreadable timeout
    // must not grant the longest session anyone had set.
    fun getSessionTimeout(): Long =
        longAt(KEY_SESSION_TIMEOUT, ifAbsent = DEFAULT_SESSION_TIMEOUT_MS, ifUnreadable = 0)

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
        // Checked for the whole record before any arithmetic, because these values live
        // in one file under one key, so a fault takes them together and the sums below
        // would be computed from guesses. Reports the longest configured lockout rather
        // than none: the throttle is what makes a short PIN worth having, and this is
        // the one case where someone able to write this file could otherwise clear it.
        // Waiting is not the way out; an unreadable record puts the unlock screen in
        // its own state, which offers the reset.
        if (pinRecord() == PinRecord.UNREADABLE) return LOCKOUT_DURATIONS_MS.last()

        val lockoutDuration = longAt(
            KEY_LOCKOUT_DURATION,
            ifAbsent = 0,
            ifUnreadable = LOCKOUT_DURATIONS_MS.last()
        )
        if (lockoutDuration == 0L) {
            maybeDecayLockoutLevel()
            return 0
        }

        // An anchor that will not decrypt is its own case rather than a number. Either
        // number is wrong: 0 makes the subtraction below expire the lockout at once, and
        // "now" substituted on each read re-anchors it to the moment of every call, which
        // holds it at full length forever. With the PIN flag reading fine the screen
        // shows the lockout and not the removal, so counting down is the only way out.
        // Writing a fresh anchor makes the lockout run its full length once and then
        // end, and the write heals the damaged value, since it does not read first.
        val setAtRead = prefs.readLong(KEY_LOCKOUT_SET_AT_ELAPSED)
        val wallRead = prefs.readLong(KEY_LOCKOUT_WALL_CLOCK)
        if (setAtRead == PrefRead.Unreadable || wallRead == PrefRead.Unreadable) {
            return reanchorLockout(lockoutDuration)
        }
        val savedSetElapsed = (setAtRead as? PrefRead.Found)?.value ?: 0L
        val currentElapsed = SystemClock.elapsedRealtime()

        val rebootDetected = currentElapsed < savedSetElapsed
        if (rebootDetected) {
            val lockoutWallClock = (wallRead as? PrefRead.Found)?.value ?: 0L
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
            val adjustedDuration = remainingByWallClock.coerceAtMost(lockoutDuration)
            prefs.edit()
                .putLong(KEY_LOCKOUT_SET_AT_ELAPSED, currentElapsed)
                .putLong(KEY_LOCKOUT_DURATION, adjustedDuration)
                .putLong(KEY_LOCKOUT_WALL_CLOCK, currentWallClock)
                .commit()
            return adjustedDuration
        }

        val remainingByElapsed = lockoutDuration - (currentElapsed - savedSetElapsed)
        if (remainingByElapsed <= 0) {
            clearLockoutTimestampsInternal()
            return 0
        }
        return remainingByElapsed
    }

    @Synchronized
    /**
     * Starts [duration] over from now, for a lockout whose anchor could not be read.
     *
     * If the write fails the next read finds the anchor still unreadable and comes back
     * here, so the lockout holds rather than lifting. That is the strict direction, at
     * the cost of a lockout that cannot end while storage refuses writes.
     */
    private fun reanchorLockout(duration: Long): Long {
        prefs.edit()
            .putLong(KEY_LOCKOUT_SET_AT_ELAPSED, SystemClock.elapsedRealtime())
            .putLong(KEY_LOCKOUT_WALL_CLOCK, System.currentTimeMillis())
            .putLong(KEY_LOCKOUT_DURATION, duration)
            .commit()
        return duration
    }

    // A reset that is owed and cannot be read is still owed.
    fun requiresBiometricReset(): Boolean =
        boolAt(KEY_BIOMETRIC_RESET_REQUIRED, ifAbsent = false, ifUnreadable = true)

    @Synchronized
    fun clearBiometricResetRequirement(): Boolean {
        val success = prefs.edit()
            .putInt(KEY_LOCKOUT_EPOCH, 0)
            .putBoolean(KEY_BIOMETRIC_RESET_REQUIRED, false)
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_SET_AT_ELAPSED, 0)
            .putLong(KEY_LOCKOUT_WALL_CLOCK, 0)
            .putLong(KEY_LOCKOUT_DURATION, 0)
            .putLong(KEY_LAST_LOCKOUT_CLEARED, System.currentTimeMillis())
            .commit()
        if (!success && BuildConfig.DEBUG) {
            Log.w("PinStore", "Failed to clear biometric reset requirement")
        }
        return success
    }

    private fun maybeDecayLockoutLevel() {
        // Decay only ever lowers the escalation level, so an unreadable level or
        // timestamp must not drive it: both answer "nothing to decay" and leave the
        // escalation where it is.
        val currentLevel = intAt(KEY_LOCKOUT_LEVEL, ifAbsent = 0, ifUnreadable = 0)
        if (currentLevel == 0) return

        val lastCleared = longAt(KEY_LAST_LOCKOUT_CLEARED, ifAbsent = 0, ifUnreadable = 0)
        if (lastCleared == 0L) return

        val now = System.currentTimeMillis()
        val elapsed = now - lastCleared
        if (elapsed < 0 || elapsed > LOCKOUT_LEVEL_DECAY_MS * (LOCKOUT_DURATIONS_MS.size + 1)) {
            prefs.edit()
                .putInt(KEY_LOCKOUT_LEVEL, 0)
                .putLong(KEY_LAST_LOCKOUT_CLEARED, now)
                .commit()
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
        val editor = prefs.edit()
            .putLong(KEY_LOCKOUT_SET_AT_ELAPSED, 0)
            .putLong(KEY_LOCKOUT_WALL_CLOCK, 0)
            .putLong(KEY_LOCKOUT_DURATION, 0)
            .putLong(KEY_LAST_LOCKOUT_CLEARED, System.currentTimeMillis())
        // Through the fail-closed read: an unreadable requirement is still owed, so the
        // attempt counter is kept rather than cleared.
        if (!requiresBiometricReset()) {
            editor.putInt(KEY_FAILED_ATTEMPTS, 0)
        }
        editor.commit()
    }

    @Synchronized
    // An unreadable counter reports the budget spent, so getRemainingAttempts answers 0
    // rather than a full allowance.
    fun getFailedAttempts(): Int =
        intAt(KEY_FAILED_ATTEMPTS, ifAbsent = 0, ifUnreadable = MAX_FAILED_ATTEMPTS)

    @Synchronized
    fun getRemainingAttempts(): Int = MAX_FAILED_ATTEMPTS - getFailedAttempts()

    private fun incrementFailedAttempts() {
        val attempts = getFailedAttempts() + 1
        val editor = prefs.edit().putInt(KEY_FAILED_ATTEMPTS, attempts)

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            // An unreadable level takes the top of the ladder, not the bottom: reading
            // it as 0 would hand out the shortest lockout and restart the escalation.
            val currentLevel = intAt(
                KEY_LOCKOUT_LEVEL,
                ifAbsent = 0,
                ifUnreadable = LOCKOUT_DURATIONS_MS.size - 1
            )
            val duration = LOCKOUT_DURATIONS_MS[currentLevel.coerceIn(0, LOCKOUT_DURATIONS_MS.size - 1)]
            val newLevel = (currentLevel + 1).coerceAtMost(LOCKOUT_DURATIONS_MS.size - 1)
            editor.putLong(KEY_LOCKOUT_SET_AT_ELAPSED, SystemClock.elapsedRealtime())
            editor.putLong(KEY_LOCKOUT_WALL_CLOCK, System.currentTimeMillis())
            editor.putLong(KEY_LOCKOUT_DURATION, duration)
            editor.putInt(KEY_FAILED_ATTEMPTS, 0)
            editor.putInt(KEY_LOCKOUT_LEVEL, newLevel)

            // An unreadable epoch counts as having reached the threshold, so the
            // biometric reset below is required rather than postponed.
            val epoch = intAt(
                KEY_LOCKOUT_EPOCH,
                ifAbsent = 0,
                ifUnreadable = LOCKOUT_EPOCHS_BEFORE_BIOMETRIC
            ) + 1
            editor.putInt(KEY_LOCKOUT_EPOCH, epoch)
            if (epoch >= LOCKOUT_EPOCHS_BEFORE_BIOMETRIC) {
                editor.putBoolean(KEY_BIOMETRIC_RESET_REQUIRED, true)
            }
        }

        if (!editor.commit()) {
            if (BuildConfig.DEBUG) Log.e("PinStore", "Failed to persist lockout state")
        }
    }

    private fun clearFailedAttemptsAndResetEpoch() {
        // 0 is the strict answer here, unlike the other level reads: it only decides
        // whether to stamp the decay clock, and not stamping leaves the escalation
        // where it is. Don't align this with the others.
        val currentLevel = intAt(KEY_LOCKOUT_LEVEL, ifAbsent = 0, ifUnreadable = 0)
        val editor = prefs.edit()
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putInt(KEY_LOCKOUT_EPOCH, 0)
            .putBoolean(KEY_BIOMETRIC_RESET_REQUIRED, false)
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
