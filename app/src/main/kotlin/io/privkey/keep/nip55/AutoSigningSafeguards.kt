package io.privkey.keep.nip55

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.util.concurrent.ConcurrentHashMap

class AutoSigningSafeguards(context: Context) {

    companion object {
        private const val PREFS_NAME = "nip55_auto_signing"
        private const val KEY_PREFIX_OPTED_IN = "opted_in_"
        private const val KEY_PREFIX_COOLED_OFF_UNTIL = "cooled_off_"

        private const val HOUR_MS = 60 * 60 * 1000L
        private const val DAY_MS = 24 * 60 * 60 * 1000L

        const val HOURLY_LIMIT = 100
        const val DAILY_LIMIT = 500
        const val COOLING_OFF_PERIOD_MS = 15 * 60 * 1000L
        const val UNUSUAL_ACTIVITY_THRESHOLD = 50
        const val UNUSUAL_ACTIVITY_WINDOW_MS = 60 * 1000L
    }

    private val prefs = run {
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

    private data class UsageWindow(var count: Int, var windowStart: Long)
    private val hourlyUsage = ConcurrentHashMap<String, UsageWindow>()
    private val dailyUsage = ConcurrentHashMap<String, UsageWindow>()
    private val recentActivity = ConcurrentHashMap<String, UsageWindow>()

    fun isOptedIn(packageName: String): Boolean =
        prefs.getBoolean(KEY_PREFIX_OPTED_IN + packageName, false)

    fun setOptedIn(packageName: String, optedIn: Boolean) {
        prefs.edit().putBoolean(KEY_PREFIX_OPTED_IN + packageName, optedIn).apply()
    }

    fun isCooledOff(packageName: String): Boolean {
        val until = prefs.getLong(KEY_PREFIX_COOLED_OFF_UNTIL + packageName, 0)
        return System.currentTimeMillis() < until
    }

    fun getCooledOffUntil(packageName: String): Long =
        prefs.getLong(KEY_PREFIX_COOLED_OFF_UNTIL + packageName, 0)

    private fun setCooledOff(packageName: String) {
        val until = System.currentTimeMillis() + COOLING_OFF_PERIOD_MS
        prefs.edit().putLong(KEY_PREFIX_COOLED_OFF_UNTIL + packageName, until).apply()
    }

    fun clearCoolingOff(packageName: String) {
        prefs.edit().remove(KEY_PREFIX_COOLED_OFF_UNTIL + packageName).apply()
    }

    fun checkAndRecordUsage(packageName: String): UsageCheckResult {
        if (isCooledOff(packageName)) {
            return UsageCheckResult.CoolingOff(getCooledOffUntil(packageName))
        }

        val now = System.currentTimeMillis()
        val hourly = incrementUsage(hourlyUsage, packageName, now, HOUR_MS)
        if (hourly.count > HOURLY_LIMIT) {
            setCooledOff(packageName)
            return UsageCheckResult.HourlyLimitExceeded
        }

        val daily = incrementUsage(dailyUsage, packageName, now, DAY_MS)
        if (daily.count > DAILY_LIMIT) {
            setCooledOff(packageName)
            return UsageCheckResult.DailyLimitExceeded
        }

        val recent = incrementUsage(recentActivity, packageName, now, UNUSUAL_ACTIVITY_WINDOW_MS)
        if (recent.count > UNUSUAL_ACTIVITY_THRESHOLD) {
            setCooledOff(packageName)
            return UsageCheckResult.UnusualActivity
        }

        return UsageCheckResult.Allowed(hourly.count, daily.count)
    }

    private fun incrementUsage(
        map: ConcurrentHashMap<String, UsageWindow>,
        packageName: String,
        now: Long,
        windowMs: Long
    ): UsageWindow = map.compute(packageName) { _, existing ->
        if (existing == null || now - existing.windowStart >= windowMs) {
            UsageWindow(1, now)
        } else {
            existing.count++
            existing
        }
    }!!

    fun getUsageStats(packageName: String): UsageStats {
        val now = System.currentTimeMillis()
        val hourly = getUsageCount(hourlyUsage, packageName, now, HOUR_MS)
        val daily = getUsageCount(dailyUsage, packageName, now, DAY_MS)
        return UsageStats(hourly, daily, HOURLY_LIMIT, DAILY_LIMIT)
    }

    private fun getUsageCount(
        map: ConcurrentHashMap<String, UsageWindow>,
        packageName: String,
        now: Long,
        windowMs: Long
    ): Int = map[packageName]?.let { if (now - it.windowStart < windowMs) it.count else 0 } ?: 0

    data class UsageStats(
        val hourlyCount: Int,
        val dailyCount: Int,
        val hourlyLimit: Int,
        val dailyLimit: Int
    )

    sealed class UsageCheckResult {
        data class Allowed(val hourlyCount: Int, val dailyCount: Int) : UsageCheckResult()
        data object HourlyLimitExceeded : UsageCheckResult()
        data object DailyLimitExceeded : UsageCheckResult()
        data object UnusualActivity : UsageCheckResult()
        data class CoolingOff(val until: Long) : UsageCheckResult()
    }
}
