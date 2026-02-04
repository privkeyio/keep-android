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
        val now = timeProvider()
        synchronized(rateLimitMap) {
            val existing = rateLimitMap[callerPackage]
            return if (existing == null || now - existing.windowStart >= windowMs) {
                rateLimitMap[callerPackage] = RateLimitEntry(1, now)
                true
            } else {
                ++existing.count <= maxRequests
            }
        }
    }
}
