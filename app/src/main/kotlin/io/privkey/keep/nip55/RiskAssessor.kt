package io.privkey.keep.nip55

import android.os.SystemClock
import java.util.Calendar

data class RiskAssessment(
    val score: Int,
    val factors: List<RiskFactor>,
    val requiredAuth: AuthLevel
)

enum class AuthLevel {
    NONE,
    PIN,
    BIOMETRIC,
    EXPLICIT
}

enum class RiskFactor(val weight: Int, val description: String) {
    SENSITIVE_EVENT_KIND(40, "Sensitive event type"),
    UNUSUAL_TIME(10, "Unusual time of day"),
    HIGH_FREQUENCY(20, "High request frequency"),
    NEW_APP(15, "Recently connected app"),
    FIRST_KIND(15, "First time signing this event type")
}

class RiskAssessor(
    private val auditDao: Nip55AuditLogDao,
    private val appSettingsDao: Nip55AppSettingsDao,
    private val elapsedRealtimeProvider: () -> Long = { SystemClock.elapsedRealtime() },
    private val currentTimeMillisProvider: () -> Long = { System.currentTimeMillis() },
    private val currentHourProvider: () -> Int = { Calendar.getInstance().get(Calendar.HOUR_OF_DAY) }
) {
    companion object {
        private const val HIGH_FREQUENCY_THRESHOLD = 10
        private const val FREQUENCY_WINDOW_MS = 60_000L
        private const val NEW_APP_THRESHOLD_MS = 24 * 60 * 60 * 1000L
        private const val MAX_TRACKED_PACKAGES = 500
    }

    private data class FrequencyWindow(val windowStart: Long, val wallClock: Long)

    private val frequencyLock = Any()
    private val frequencyWindows = HashMap<String, FrequencyWindow>()

    suspend fun assess(packageName: String, eventKind: Int?): RiskAssessment {
        val factors = mutableListOf<RiskFactor>()

        if (eventKind != null) {
            if (isSensitiveKind(eventKind)) {
                factors.add(RiskFactor.SENSITIVE_EVENT_KIND)
            }
            if (auditDao.countByPackageAndKind(packageName, eventKind) == 0) {
                factors.add(RiskFactor.FIRST_KIND)
            }
        }

        val frequencySince = synchronized(frequencyLock) {
            val nowElapsed = elapsedRealtimeProvider()
            val existing = frequencyWindows[packageName]
            val windowStale = existing == null ||
                (nowElapsed - existing.windowStart).let { it < 0 || it > FREQUENCY_WINDOW_MS * 2 }

            val window = if (windowStale) {
                FrequencyWindow(nowElapsed, currentTimeMillisProvider()).also {
                    frequencyWindows[packageName] = it
                }
            } else {
                existing!!
            }

            if (frequencyWindows.size > MAX_TRACKED_PACKAGES) {
                val oldest = frequencyWindows.entries.minByOrNull { it.value.windowStart }?.key
                if (oldest != null && oldest != packageName) frequencyWindows.remove(oldest)
            }
            (window.wallClock - FREQUENCY_WINDOW_MS + (nowElapsed - window.windowStart)).coerceAtLeast(0)
        }
        val recentCount = auditDao.countSince(packageName, frequencySince)
        if (recentCount > HIGH_FREQUENCY_THRESHOLD) {
            factors.add(RiskFactor.HIGH_FREQUENCY)
        }

        val hour = currentHourProvider()
        if (hour < 6 || hour >= 23) {
            factors.add(RiskFactor.UNUSUAL_TIME)
        }

        val appSettings = appSettingsDao.getSettings(packageName)
        if (appSettings == null) {
            factors.add(RiskFactor.NEW_APP)
        } else {
            val nowElapsed = elapsedRealtimeProvider()
            val useMonotonic = appSettings.createdAtElapsed > 0 && nowElapsed > appSettings.createdAtElapsed
            val appAge = if (useMonotonic) {
                nowElapsed - appSettings.createdAtElapsed
            } else {
                (currentTimeMillisProvider() - appSettings.createdAt).coerceAtLeast(0)
            }
            if (appAge < NEW_APP_THRESHOLD_MS) {
                factors.add(RiskFactor.NEW_APP)
            }
        }

        val score = factors.sumOf { it.weight }.coerceAtMost(100)
        val requiredAuth = when {
            score >= 60 -> AuthLevel.EXPLICIT
            score >= 40 -> AuthLevel.BIOMETRIC
            score >= 20 -> AuthLevel.PIN
            else -> AuthLevel.NONE
        }

        return RiskAssessment(score, factors, requiredAuth)
    }
}
