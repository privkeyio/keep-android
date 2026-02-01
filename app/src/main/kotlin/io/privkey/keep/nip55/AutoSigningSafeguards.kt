package io.privkey.keep.nip55

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class AutoSigningSafeguards(context: Context) {

    companion object {
        private const val PREFS_NAME = "nip55_auto_signing"
        private const val KEY_PREFIX_OPTED_IN = "opted_in_"
        private const val KEY_PREFIX_COOLED_OFF_UNTIL = "cooled_off_"
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

    fun isCooledOff(packageName: String): Boolean =
        System.currentTimeMillis() < getCooledOffUntil(packageName)

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
        synchronized(usageLock) {
            val hourly = incrementUsage(hourlyUsage, KEY_PREFIX_HOURLY, packageName, now, HOUR_MS)
            if (hourly.count > HOURLY_LIMIT) {
                setCooledOff(packageName)
                return UsageCheckResult.HourlyLimitExceeded
            }

            val daily = incrementUsage(dailyUsage, KEY_PREFIX_DAILY, packageName, now, DAY_MS)
            if (daily.count > DAILY_LIMIT) {
                setCooledOff(packageName)
                return UsageCheckResult.DailyLimitExceeded
            }

            val recent = incrementUsage(recentActivity, null, packageName, now, UNUSUAL_ACTIVITY_WINDOW_MS)
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
        now: Long,
        windowMs: Long
    ): UsageWindow {
        val existing = map[packageName] ?: persistKeyPrefix?.let { loadPersistedUsage(it, packageName) }
        val entry = if (existing == null || now - existing.windowStart >= windowMs) {
            UsageWindow(1, now)
        } else {
            existing.count++
            existing
        }
        map[packageName] = entry
        persistKeyPrefix?.let { persistUsage(it, packageName, entry) }
        return entry
    }

    private fun loadPersistedUsage(keyPrefix: String, packageName: String): UsageWindow? {
        val key = keyPrefix + packageName
        val value = prefs.getString(key, null) ?: return null
        val parts = value.split(":")
        if (parts.size != 2) return null
        val count = parts[0].toIntOrNull() ?: return null
        val windowStart = parts[1].toLongOrNull() ?: return null
        return UsageWindow(count, windowStart)
    }

    private fun persistUsage(keyPrefix: String, packageName: String, usage: UsageWindow) {
        val key = keyPrefix + packageName
        prefs.edit().putString(key, "${usage.count}:${usage.windowStart}").apply()
    }

    fun getUsageStats(packageName: String): UsageStats {
        val now = System.currentTimeMillis()
        synchronized(usageLock) {
            val hourly = getUsageCount(hourlyUsage, KEY_PREFIX_HOURLY, packageName, now, HOUR_MS)
            val daily = getUsageCount(dailyUsage, KEY_PREFIX_DAILY, packageName, now, DAY_MS)
            return UsageStats(hourly, daily, HOURLY_LIMIT, DAILY_LIMIT)
        }
    }

    private fun getUsageCount(
        map: LinkedHashMap<String, UsageWindow>,
        persistKeyPrefix: String,
        packageName: String,
        now: Long,
        windowMs: Long
    ): Int {
        val usage = map[packageName] ?: loadPersistedUsage(persistKeyPrefix, packageName)
        return usage?.let { if (now - it.windowStart < windowMs) it.count else 0 } ?: 0
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
