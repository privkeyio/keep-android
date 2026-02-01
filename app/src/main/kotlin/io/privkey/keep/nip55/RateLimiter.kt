package io.privkey.keep.nip55

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class RateLimiter(
    val windowMs: Long = 1000L,
    val maxRequests: Int = 10,
    private val maxEntries: Int = 1000,
    private val cleanupIntervalMs: Long = 60_000L
) {
    data class RateLimitEntry(
        val count: AtomicInteger,
        val windowStart: AtomicLong
    )

    internal val rateLimitMap = ConcurrentHashMap<String, RateLimitEntry>()
    private val lastCleanup = AtomicLong(0)

    fun checkRateLimit(callerPackage: String): Boolean {
        val now = System.currentTimeMillis()
        maybeCleanup(now)
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

    private fun maybeCleanup(now: Long) {
        val last = lastCleanup.get()
        if (now - last < cleanupIntervalMs && rateLimitMap.size <= maxEntries) return
        if (!lastCleanup.compareAndSet(last, now)) return
        val expiredThreshold = now - windowMs
        rateLimitMap.entries.removeIf { it.value.windowStart.get() < expiredThreshold }
    }
}
