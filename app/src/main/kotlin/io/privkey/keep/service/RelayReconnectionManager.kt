package io.privkey.keep.service

import android.os.SystemClock
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min

/**
 * Manages exponential backoff for relay reconnection attempts.
 * Thread-safe implementation that prevents flooding relays with connection attempts.
 */
class RelayReconnectionManager {
    private val relayBackoffState = ConcurrentHashMap<String, BackoffState>()
    private val lock = Any()
    private val secureRandom = SecureRandom()

    data class BackoffState(
        val attempts: Int = 0,
        val lastAttemptTime: Long = 0L
    )

    private fun isValidRelayUrl(url: String): Boolean {
        if (url.length > MAX_URL_LENGTH) return false
        return url.startsWith("wss://")
    }

    private fun evictOldestIfNeeded() {
        if (relayBackoffState.size <= MAX_TRACKED_RELAYS) return
        val oldest = relayBackoffState.entries
            .filter { it.value.attempts >= MIN_ATTEMPTS_FOR_EVICTION }
            .minByOrNull { it.value.lastAttemptTime }
            ?.key
        oldest?.let { relayBackoffState.remove(it) }
    }

    /**
     * Atomically checks if reconnection should be attempted and records the attempt.
     * Combines check-and-record to prevent TOCTOU race conditions.
     *
     * @return true if reconnection should be attempted, false if still in backoff or invalid URL
     */
    fun tryAttemptReconnect(relayUrl: String): Boolean {
        if (!isValidRelayUrl(relayUrl)) return false
        synchronized(lock) {
            evictOldestIfNeeded()
            val now = SystemClock.elapsedRealtime()
            val state = relayBackoffState[relayUrl]

            if (state != null) {
                if (state.attempts >= MAX_ATTEMPTS) return false
                val delayMs = calculateDelay(state.attempts)
                if (now - state.lastAttemptTime < delayMs) return false
            }

            val currentAttempts = state?.attempts ?: 0
            val newAttempts = (currentAttempts + 1).coerceAtMost(MAX_ATTEMPTS)
            relayBackoffState[relayUrl] = BackoffState(
                attempts = newAttempts,
                lastAttemptTime = now
            )
            return true
        }
    }

    /**
     * Gets the delay until next reconnection attempt is allowed.
     * Returns 0 if reconnection can happen immediately or URL is invalid.
     * Returns Long.MAX_VALUE if max attempts exhausted.
     */
    fun getDelayForRelay(relayUrl: String): Long {
        if (!isValidRelayUrl(relayUrl)) return 0L
        synchronized(lock) {
            val state = relayBackoffState[relayUrl] ?: return 0L
            if (state.attempts >= MAX_ATTEMPTS) return Long.MAX_VALUE
            val delayMs = calculateDelay(state.attempts)
            val elapsed = SystemClock.elapsedRealtime() - state.lastAttemptTime
            return (delayMs - elapsed).coerceAtLeast(0L)
        }
    }

    /**
     * Resets backoff state for a specific relay.
     * Call this on successful connection or when manually resetting a relay.
     */
    fun reset(relayUrl: String) {
        relayBackoffState.remove(relayUrl)
    }

    /**
     * Resets all backoff state (e.g., on network change).
     */
    fun resetAll() {
        relayBackoffState.clear()
    }

    /**
     * Checks if max reconnection attempts have been exhausted for a relay.
     * Returns false for invalid URLs.
     */
    fun hasExhaustedAttempts(relayUrl: String): Boolean {
        if (!isValidRelayUrl(relayUrl)) return false
        val state = relayBackoffState[relayUrl] ?: return false
        return state.attempts >= MAX_ATTEMPTS
    }

    private fun calculateDelay(attempts: Int): Long {
        if (attempts == 0) return 0L
        val baseDelay = INITIAL_DELAY_MS * (1L shl (attempts - 1).coerceAtMost(10))
        val cappedDelay = min(baseDelay, MAX_DELAY_MS)
        val jitterRange = (cappedDelay * JITTER_FACTOR).toLong()
        val jitter = if (jitterRange > 0) {
            // Use nextDouble() for API 33 compatibility (nextLong(bound) requires API 35)
            (secureRandom.nextDouble() * jitterRange * 2 - jitterRange).toLong()
        } else 0L
        return (cappedDelay + jitter).coerceIn(INITIAL_DELAY_MS, MAX_DELAY_MS)
    }

    companion object {
        const val INITIAL_DELAY_MS = 200L
        const val MAX_DELAY_MS = 30_000L
        const val MAX_ATTEMPTS = 10
        const val JITTER_FACTOR = 0.2
        const val MAX_URL_LENGTH = 2048
        const val MAX_TRACKED_RELAYS = 100
        const val MIN_ATTEMPTS_FOR_EVICTION = 3
    }
}
