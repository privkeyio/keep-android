package io.privkey.keep.nip55

import android.util.LruCache
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class RateLimiter(
    val windowMs: Long = 1000L,
    val maxRequests: Int = 10,
    maxEntries: Int = 1000
) {
    data class RateLimitEntry(
        val count: AtomicInteger,
        val windowStart: AtomicLong
    )

    private val rateLimitMap = LruCache<String, RateLimitEntry>(maxEntries)

    fun checkRateLimit(callerPackage: String): Boolean {
        val now = System.currentTimeMillis()
        synchronized(rateLimitMap) {
            val existing = rateLimitMap.get(callerPackage)
            return if (existing == null || now - existing.windowStart.get() >= windowMs) {
                rateLimitMap.put(callerPackage, RateLimitEntry(AtomicInteger(1), AtomicLong(now)))
                true
            } else {
                existing.count.incrementAndGet() <= maxRequests
            }
        }
    }
}
