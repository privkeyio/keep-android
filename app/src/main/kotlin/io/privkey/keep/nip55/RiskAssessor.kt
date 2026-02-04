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
    private val appSettingsDao: Nip55AppSettingsDao
) {
    companion object {
        private const val HIGH_FREQUENCY_THRESHOLD = 10
        private const val FREQUENCY_WINDOW_MS = 60_000L
        private const val NEW_APP_THRESHOLD_MS = 24 * 60 * 60 * 1000L
    }

    private val frequencyLock = Any()
    @Volatile private var frequencyWindowStart: Long = SystemClock.elapsedRealtime()
    @Volatile private var frequencyWindowWallClock: Long = System.currentTimeMillis()

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
            val nowElapsedFreq = SystemClock.elapsedRealtime()
            val elapsedSinceWindowStart = nowElapsedFreq - frequencyWindowStart
            if (elapsedSinceWindowStart < 0 || elapsedSinceWindowStart > FREQUENCY_WINDOW_MS * 2) {
                frequencyWindowStart = nowElapsedFreq
                frequencyWindowWallClock = System.currentTimeMillis()
            }
            (frequencyWindowWallClock - FREQUENCY_WINDOW_MS +
                (nowElapsedFreq - frequencyWindowStart)).coerceAtLeast(0)
        }
        val recentCount = auditDao.countSince(packageName, frequencySince)
        if (recentCount > HIGH_FREQUENCY_THRESHOLD) {
            factors.add(RiskFactor.HIGH_FREQUENCY)
        }

        val hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)
        if (hour < 6 || hour >= 23) {
            factors.add(RiskFactor.UNUSUAL_TIME)
        }

        appSettingsDao.getSettings(packageName)?.let { appSettings ->
            val nowElapsed = SystemClock.elapsedRealtime()
            val useMonotonic = appSettings.createdAtElapsed > 0 && nowElapsed > appSettings.createdAtElapsed
            val appAge = if (useMonotonic) {
                nowElapsed - appSettings.createdAtElapsed
            } else {
                System.currentTimeMillis() - appSettings.createdAt
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
