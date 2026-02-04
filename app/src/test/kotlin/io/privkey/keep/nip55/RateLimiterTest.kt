package io.privkey.keep.nip55

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger

class RateLimiterTest {

    private lateinit var rateLimiter: RateLimiter
    private var currentTime = 0L

    @Before
    fun setup() {
        currentTime = 0L
        rateLimiter = RateLimiter(windowMs = 1000L, maxRequests = 10, timeProvider = { currentTime })
    }

    @Test
    fun `first request is allowed`() {
        assertTrue(rateLimiter.checkRateLimit("com.test.app"))
    }

    @Test
    fun `requests within limit are allowed`() {
        val caller = "com.test.app"
        for (i in 1..rateLimiter.maxRequests) {
            assertTrue("Request $i should be allowed", rateLimiter.checkRateLimit(caller))
        }
    }

    @Test
    fun `request exceeding limit is denied`() {
        val caller = "com.test.app"
        for (i in 1..rateLimiter.maxRequests) {
            rateLimiter.checkRateLimit(caller)
        }
        assertFalse(rateLimiter.checkRateLimit(caller))
    }

    @Test
    fun `different callers have separate limits`() {
        val caller1 = "com.test.app1"
        val caller2 = "com.test.app2"

        for (i in 1..rateLimiter.maxRequests) {
            rateLimiter.checkRateLimit(caller1)
        }
        assertFalse(rateLimiter.checkRateLimit(caller1))
        assertTrue(rateLimiter.checkRateLimit(caller2))
    }

    @Test
    fun `rate limit resets after window`() {
        var currentTime = 0L
        val shortWindowLimiter = RateLimiter(
            windowMs = 100L,
            maxRequests = 2,
            timeProvider = { currentTime }
        )
        val caller = "com.test.app"

        assertTrue(shortWindowLimiter.checkRateLimit(caller))
        assertTrue(shortWindowLimiter.checkRateLimit(caller))
        assertFalse(shortWindowLimiter.checkRateLimit(caller))

        currentTime = 101L

        assertTrue(shortWindowLimiter.checkRateLimit(caller))
    }

    @Test
    fun `concurrent requests from same caller are tracked correctly`() {
        val caller = "com.test.app"
        val totalRequests = rateLimiter.maxRequests + 5
        val latch = CountDownLatch(1)
        val allowedCount = AtomicInteger(0)
        val deniedCount = AtomicInteger(0)

        val threads = (1..totalRequests).map {
            Thread {
                latch.await()
                val allowed = rateLimiter.checkRateLimit(caller)
                if (allowed) {
                    allowedCount.incrementAndGet()
                } else {
                    deniedCount.incrementAndGet()
                }
            }
        }
        threads.forEach { it.start() }
        latch.countDown()
        threads.forEach { it.join() }

        assertEquals(rateLimiter.maxRequests, allowedCount.get())
        assertEquals(totalRequests - rateLimiter.maxRequests, deniedCount.get())
    }

    @Test
    fun `empty caller package is handled`() {
        assertTrue(rateLimiter.checkRateLimit(""))
    }

    @Test
    fun `special characters in caller package are handled`() {
        assertTrue(rateLimiter.checkRateLimit("com.test.app_123-special"))
    }
}
