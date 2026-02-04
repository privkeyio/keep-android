package io.privkey.keep.nip55

import android.os.SystemClock
import android.util.LruCache

class RateLimiter(
    val windowMs: Long = 1000L,
    val maxRequests: Int = 10,
    maxEntries: Int = 1000
) {
    private data class RateLimitEntry(
        var count: Int,
        var windowStart: Long
    )

    private val rateLimitMap = LruCache<String, RateLimitEntry>(maxEntries)

    fun checkRateLimit(callerPackage: String): Boolean {
        val now = SystemClock.elapsedRealtime()
        synchronized(rateLimitMap) {
            val existing = rateLimitMap.get(callerPackage)
            return if (existing == null || now - existing.windowStart >= windowMs) {
                rateLimitMap.put(callerPackage, RateLimitEntry(1, now))
                true
            } else {
                ++existing.count <= maxRequests
            }
        }
    }
}
