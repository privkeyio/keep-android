package io.privkey.keep.nip55

import android.os.SystemClock

class RateLimiter(
    val windowMs: Long = 1000L,
    val maxRequests: Int = 10,
    private val maxEntries: Int = 1000,
    private val timeProvider: () -> Long = { SystemClock.elapsedRealtime() }
) {
    private data class RateLimitEntry(
        var count: Int,
        var windowStart: Long
    )

    private val rateLimitMap = object : LinkedHashMap<String, RateLimitEntry>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, RateLimitEntry>?): Boolean {
            return size > maxEntries
        }
    }

    fun checkRateLimit(callerPackage: String): Boolean {
        if (callerPackage.isBlank()) return false
        val now = timeProvider()
        synchronized(rateLimitMap) {
            val existing = rateLimitMap[callerPackage]
            if (existing == null) {
                rateLimitMap[callerPackage] = RateLimitEntry(1, now)
                return true
            }
            if (now - existing.windowStart >= windowMs) {
                existing.count = 1
                existing.windowStart = now
                return true
            }
            return ++existing.count <= maxRequests
        }
    }
}
