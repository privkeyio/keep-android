package io.privkey.keep.nip55

import android.os.SystemClock
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.SigningRequestContext
import io.privkey.keep.uniffi.SigningRiskAssessment
import io.privkey.keep.uniffi.SigningAuthLevel
import io.privkey.keep.uniffi.SigningRiskFactor
import io.privkey.keep.uniffi.assessSigningRisk
import java.util.Calendar

data class RiskAssessment(
    val score: Int,
    val factors: List<RiskFactor>,
    val requiredAuth: AuthLevel
)

enum class AuthLevel(val level: Int) {
    NONE(0),
    PIN(1),
    BIOMETRIC(2),
    EXPLICIT(3);

    fun atLeast(other: AuthLevel): Boolean = this.level >= other.level
}

enum class RiskFactor(val weight: Int, val description: String) {
    SENSITIVE_EVENT_KIND(40, "Sensitive event type"),
    SENSITIVE_OPERATION(40, "Sensitive operation type"),
    UNUSUAL_TIME(10, "Unusual time of day"),
    HIGH_FREQUENCY(20, "High request frequency"),
    NEW_APP(15, "Recently connected app"),
    UNKNOWN_AGE(5, "Unknown app age"),
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
        private const val FREQUENCY_WINDOW_MS = 60_000L
        private const val NEW_APP_THRESHOLD_MS = 24 * 60 * 60 * 1000L
        private const val MAX_TRACKED_PACKAGES = 500
    }

    private data class FrequencyWindow(val windowStart: Long, val wallClock: Long)

    private val frequencyLock = Any()
    private val frequencyWindows = HashMap<String, FrequencyWindow>()

    suspend fun assess(
        packageName: String,
        eventKind: Int?,
        requestType: Nip55RequestType = Nip55RequestType.SIGN_EVENT
    ): RiskAssessment {
        val recentCount = getRecentRequestCount(packageName)
        val hasSignedKindBefore = if (eventKind != null) {
            auditDao.countByPackageAndKind(packageName, eventKind) > 0
        } else {
            true
        }
        val appAgeMs = getAppAgeMs(packageName)

        val ctx = SigningRequestContext(
            operation = requestType,
            packageName = packageName,
            eventKind = eventKind?.takeIf { it >= 0 }?.toUInt(),
            hasSignedKindBefore = hasSignedKindBefore,
            appAgeMs = appAgeMs?.toULong()
        )

        val rustResult = assessSigningRisk(ctx, recentCount.toUInt(), currentHourProvider().toUInt())
        return mapFromRust(rustResult)
    }

    private suspend fun getRecentRequestCount(packageName: String): Int {
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
                checkNotNull(existing)
            }

            if (frequencyWindows.size > MAX_TRACKED_PACKAGES) {
                val oldest = frequencyWindows.entries.minByOrNull { it.value.windowStart }?.key
                if (oldest != null && oldest != packageName) frequencyWindows.remove(oldest)
            }
            (window.wallClock - FREQUENCY_WINDOW_MS + (nowElapsed - window.windowStart)).coerceAtLeast(0)
        }
        return auditDao.countSince(packageName, frequencySince)
    }

    private suspend fun getAppAgeMs(packageName: String): Long? {
        val appSettings = appSettingsDao.getSettings(packageName) ?: return null
        val nowElapsed = elapsedRealtimeProvider()
        val useMonotonic = appSettings.createdAtElapsed > 0 && nowElapsed > appSettings.createdAtElapsed
        return if (useMonotonic) {
            nowElapsed - appSettings.createdAtElapsed
        } else {
            (currentTimeMillisProvider() - appSettings.createdAt).coerceAtLeast(0)
        }
    }

    private fun mapFromRust(rust: SigningRiskAssessment): RiskAssessment {
        val factors = rust.factors.mapNotNull { factor ->
            when (factor) {
                SigningRiskFactor.SENSITIVE_EVENT_KIND -> RiskFactor.SENSITIVE_EVENT_KIND
                SigningRiskFactor.SENSITIVE_OPERATION -> RiskFactor.SENSITIVE_OPERATION
                SigningRiskFactor.UNUSUAL_TIME -> RiskFactor.UNUSUAL_TIME
                SigningRiskFactor.HIGH_FREQUENCY -> RiskFactor.HIGH_FREQUENCY
                SigningRiskFactor.NEW_APP -> RiskFactor.NEW_APP
                SigningRiskFactor.UNKNOWN_AGE -> RiskFactor.UNKNOWN_AGE
                SigningRiskFactor.FIRST_KIND -> RiskFactor.FIRST_KIND
            }
        }
        val authLevel = when (rust.requiredAuth) {
            SigningAuthLevel.NONE -> AuthLevel.NONE
            SigningAuthLevel.PIN -> AuthLevel.PIN
            SigningAuthLevel.BIOMETRIC -> AuthLevel.BIOMETRIC
            SigningAuthLevel.EXPLICIT -> AuthLevel.EXPLICIT
        }
        return RiskAssessment(rust.score.toInt(), factors, authLevel)
    }
}
