package io.privkey.keep.nip55

import android.content.Context
import android.os.SystemClock
import io.privkey.keep.storage.KeystoreEncryptedPrefs

class AutoSigningSafeguards(context: Context) {

    companion object {
        private const val PREFS_NAME = "nip55_auto_signing"
        private const val KEY_PREFIX_OPTED_IN = "opted_in_"
        private const val KEY_PREFIX_COOLED_OFF_UNTIL = "cooled_off_"
        private const val KEY_PREFIX_COOLED_OFF_ELAPSED = "cooled_off_elapsed_"
        private const val KEY_PREFIX_HOURLY = "hourly_"
        private const val KEY_PREFIX_DAILY = "daily_"

        private const val HOUR_MS = 60 * 60 * 1000L
        private const val DAY_MS = 24 * 60 * 60 * 1000L

        const val HOURLY_LIMIT = 100
        const val DAILY_LIMIT = 500
        const val COOLING_OFF_PERIOD_MS = 15 * 60 * 1000L
        const val UNUSUAL_ACTIVITY_THRESHOLD = 50
        const val UNUSUAL_ACTIVITY_WINDOW_MS = 60 * 1000L

        private const val MAX_TRACKED_PACKAGES = 500
    }

    private val prefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    private data class UsageWindow(var count: Int, var windowStartElapsed: Long)

    private val usageLock = Any()
    private val hourlyUsage = createLruUsageMap()
    private val dailyUsage = createLruUsageMap()
    private val recentActivity = createLruUsageMap()

    private fun createLruUsageMap(): LinkedHashMap<String, UsageWindow> =
        object : LinkedHashMap<String, UsageWindow>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, UsageWindow>?): Boolean =
                size > MAX_TRACKED_PACKAGES
        }

    fun isOptedIn(packageName: String): Boolean =
        prefs.getBoolean(KEY_PREFIX_OPTED_IN + packageName, false)

    fun setOptedIn(packageName: String, optedIn: Boolean) {
        prefs.edit().putBoolean(KEY_PREFIX_OPTED_IN + packageName, optedIn).apply()
    }

    fun isCooledOff(packageName: String): Boolean {
        val nowElapsed = SystemClock.elapsedRealtime()
        val cooledOffUntilElapsed = prefs.getLong(KEY_PREFIX_COOLED_OFF_ELAPSED + packageName, 0)
        if (cooledOffUntilElapsed > 0 &&
            nowElapsed < cooledOffUntilElapsed &&
            cooledOffUntilElapsed - nowElapsed <= COOLING_OFF_PERIOD_MS) {
            return true
        }
        val cooledOffUntilWall = prefs.getLong(KEY_PREFIX_COOLED_OFF_UNTIL + packageName, 0)
        return cooledOffUntilWall > 0 && System.currentTimeMillis() < cooledOffUntilWall
    }

    fun getCooledOffUntil(packageName: String): Long {
        val nowElapsed = SystemClock.elapsedRealtime()
        val nowWall = System.currentTimeMillis()

        val cooledOffUntilWall = prefs.getLong(KEY_PREFIX_COOLED_OFF_UNTIL + packageName, 0)
        val cooledOffUntilElapsed = prefs.getLong(KEY_PREFIX_COOLED_OFF_ELAPSED + packageName, 0)

        val wallExpiryValid = cooledOffUntilWall > 0 && nowWall < cooledOffUntilWall
        val elapsedExpiryValid = cooledOffUntilElapsed > 0 &&
            nowElapsed < cooledOffUntilElapsed &&
            cooledOffUntilElapsed - nowElapsed <= COOLING_OFF_PERIOD_MS

        if (!wallExpiryValid && !elapsedExpiryValid) {
            return 0
        }

        val wallExpiry = if (wallExpiryValid) cooledOffUntilWall else Long.MAX_VALUE
        val elapsedExpiry = if (elapsedExpiryValid) {
            nowWall + (cooledOffUntilElapsed - nowElapsed)
        } else {
            Long.MAX_VALUE
        }

        return minOf(wallExpiry, elapsedExpiry)
    }

    private fun setCooledOff(packageName: String) {
        val nowElapsed = SystemClock.elapsedRealtime()
        val until = System.currentTimeMillis() + COOLING_OFF_PERIOD_MS
        val untilElapsed = nowElapsed + COOLING_OFF_PERIOD_MS
        prefs.edit()
            .putLong(KEY_PREFIX_COOLED_OFF_UNTIL + packageName, until)
            .putLong(KEY_PREFIX_COOLED_OFF_ELAPSED + packageName, untilElapsed)
            .apply()
    }

    fun clearCoolingOff(packageName: String) {
        synchronized(usageLock) {
            prefs.edit()
                .remove(KEY_PREFIX_COOLED_OFF_UNTIL + packageName)
                .remove(KEY_PREFIX_COOLED_OFF_ELAPSED + packageName)
                .apply()
        }
    }

    fun checkAndRecordUsage(packageName: String): UsageCheckResult {
        val nowElapsed = SystemClock.elapsedRealtime()
        synchronized(usageLock) {
            if (isCooledOff(packageName)) {
                return UsageCheckResult.CoolingOff(getCooledOffUntil(packageName))
            }

            val hourly = incrementUsage(hourlyUsage, KEY_PREFIX_HOURLY, packageName, nowElapsed, HOUR_MS)
            if (hourly.count > HOURLY_LIMIT) {
                setCooledOff(packageName)
                return UsageCheckResult.HourlyLimitExceeded
            }

            val daily = incrementUsage(dailyUsage, KEY_PREFIX_DAILY, packageName, nowElapsed, DAY_MS)
            if (daily.count > DAILY_LIMIT) {
                setCooledOff(packageName)
                return UsageCheckResult.DailyLimitExceeded
            }

            val recent = incrementUsage(recentActivity, null, packageName, nowElapsed, UNUSUAL_ACTIVITY_WINDOW_MS)
            if (recent.count > UNUSUAL_ACTIVITY_THRESHOLD) {
                setCooledOff(packageName)
                return UsageCheckResult.UnusualActivity
            }

            return UsageCheckResult.Allowed(hourly.count, daily.count)
        }
    }

    private fun incrementUsage(
        map: LinkedHashMap<String, UsageWindow>,
        persistKeyPrefix: String?,
        packageName: String,
        nowElapsed: Long,
        windowMs: Long
    ): UsageWindow {
        val existing = map[packageName] ?: persistKeyPrefix?.let { loadPersistedUsage(it, packageName, nowElapsed) }
        val windowExpired = existing == null ||
            existing.windowStartElapsed > nowElapsed ||
            nowElapsed - existing.windowStartElapsed >= windowMs

        val entry = if (windowExpired) {
            UsageWindow(1, nowElapsed)
        } else {
            existing!!.count++
            existing
        }
        map[packageName] = entry
        persistKeyPrefix?.let { persistUsage(it, packageName, entry) }
        return entry
    }

    private fun loadPersistedUsage(keyPrefix: String, packageName: String, nowElapsed: Long): UsageWindow? {
        val key = keyPrefix + packageName
        val value = prefs.getString(key, null) ?: return null
        val parts = value.split(":")
        if (parts.size < 2) return null
        val count = (parts[0].toIntOrNull() ?: return null).coerceIn(0, DAILY_LIMIT + 1)
        val windowStartElapsed = parts[1].toLongOrNull() ?: return null

        if (windowStartElapsed <= nowElapsed) {
            return UsageWindow(count, windowStartElapsed)
        }

        if (parts.size >= 3) {
            val windowStartWall = parts[2].toLongOrNull()
            if (windowStartWall != null) {
                val nowWall = System.currentTimeMillis()
                val elapsedSinceWindowStart = nowWall - windowStartWall
                if (elapsedSinceWindowStart >= 0) {
                    val reconstructedElapsed = nowElapsed - elapsedSinceWindowStart
                    if (reconstructedElapsed > 0) {
                        return UsageWindow(count, reconstructedElapsed)
                    }
                }
            }
        }

        return null
    }

    private fun persistUsage(keyPrefix: String, packageName: String, usage: UsageWindow) {
        val key = keyPrefix + packageName
        val wallClock = System.currentTimeMillis()
        prefs.edit().putString(key, "${usage.count}:${usage.windowStartElapsed}:$wallClock").apply()
    }

    fun getUsageStats(packageName: String): UsageStats {
        val nowElapsed = SystemClock.elapsedRealtime()
        synchronized(usageLock) {
            val hourly = getUsageCount(hourlyUsage, KEY_PREFIX_HOURLY, packageName, nowElapsed, HOUR_MS)
            val daily = getUsageCount(dailyUsage, KEY_PREFIX_DAILY, packageName, nowElapsed, DAY_MS)
            return UsageStats(hourly, daily, HOURLY_LIMIT, DAILY_LIMIT)
        }
    }

    private fun getUsageCount(
        map: LinkedHashMap<String, UsageWindow>,
        persistKeyPrefix: String,
        packageName: String,
        nowElapsed: Long,
        windowMs: Long
    ): Int {
        val usage = map[packageName] ?: loadPersistedUsage(persistKeyPrefix, packageName, nowElapsed) ?: return 0
        val elapsed = usage.windowStartElapsed
        if (elapsed > nowElapsed) return 0
        return if (nowElapsed - elapsed < windowMs) usage.count else 0
    }

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
