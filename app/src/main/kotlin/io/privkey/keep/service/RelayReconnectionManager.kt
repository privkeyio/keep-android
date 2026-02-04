package io.privkey.keep.service

import android.os.SystemClock
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min
import kotlin.random.Random

class RelayReconnectionManager {
    private val relayBackoffState = ConcurrentHashMap<String, BackoffState>()
    private val lock = Any()

    data class BackoffState(
        val attempts: Int = 0,
        val lastAttemptTime: Long = 0L
    )

    fun shouldAttemptReconnect(relayUrl: String): Boolean {
        val now = SystemClock.elapsedRealtime()
        val state = relayBackoffState[relayUrl] ?: return true
        if (state.attempts >= MAX_ATTEMPTS) return false
        val delayMs = calculateDelay(state.attempts)
        return now - state.lastAttemptTime >= delayMs
    }

    fun getDelayForRelay(relayUrl: String): Long {
        val state = relayBackoffState[relayUrl] ?: return 0L
        if (state.attempts >= MAX_ATTEMPTS) return Long.MAX_VALUE
        val delayMs = calculateDelay(state.attempts)
        val elapsed = SystemClock.elapsedRealtime() - state.lastAttemptTime
        return (delayMs - elapsed).coerceAtLeast(0L)
    }

    fun recordAttempt(relayUrl: String) {
        synchronized(lock) {
            val current = relayBackoffState[relayUrl] ?: BackoffState()
            val newAttempts = (current.attempts + 1).coerceAtMost(MAX_ATTEMPTS)
            relayBackoffState[relayUrl] = BackoffState(
                attempts = newAttempts,
                lastAttemptTime = SystemClock.elapsedRealtime()
            )
        }
    }

    fun recordSuccess(relayUrl: String) {
        relayBackoffState.remove(relayUrl)
    }

    fun resetAll() {
        relayBackoffState.clear()
    }

    fun reset(relayUrl: String) {
        relayBackoffState.remove(relayUrl)
    }

    fun hasExhaustedAttempts(relayUrl: String): Boolean {
        val state = relayBackoffState[relayUrl] ?: return false
        return state.attempts >= MAX_ATTEMPTS
    }

    private fun calculateDelay(attempts: Int): Long {
        if (attempts == 0) return 0L
        val baseDelay = INITIAL_DELAY_MS * (1L shl (attempts - 1).coerceAtMost(10))
        val cappedDelay = min(baseDelay, MAX_DELAY_MS)
        val jitter = (cappedDelay * JITTER_FACTOR * (Random.nextDouble() * 2 - 1)).toLong()
        return (cappedDelay + jitter).coerceIn(INITIAL_DELAY_MS, MAX_DELAY_MS)
    }

    companion object {
        const val INITIAL_DELAY_MS = 200L
        const val MAX_DELAY_MS = 30_000L
        const val MAX_ATTEMPTS = 10
        const val JITTER_FACTOR = 0.2
    }
}
