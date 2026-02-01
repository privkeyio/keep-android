package io.privkey.keep.nip55

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class RateLimiter(
    val windowMs: Long = 1000L,
    val maxRequests: Int = 10
) {
    data class RateLimitEntry(
        val count: AtomicInteger,
        val windowStart: AtomicLong
    )

    internal val rateLimitMap = ConcurrentHashMap<String, RateLimitEntry>()

    fun checkRateLimit(callerPackage: String): Boolean {
        val now = System.currentTimeMillis()
        var requestCount = 0
        rateLimitMap.compute(callerPackage) { _, existing ->
            if (existing == null || now - existing.windowStart.get() >= windowMs) {
                requestCount = 1
                RateLimitEntry(AtomicInteger(1), AtomicLong(now))
            } else {
                requestCount = existing.count.incrementAndGet()
                existing
            }
        }
        return requestCount <= maxRequests
    }
}
