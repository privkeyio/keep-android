package io.privkey.keep.nip55

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap

class RateLimiterTest {

    private data class RateLimitEntry(var count: Int, var windowStart: Long)
    private lateinit var rateLimitMap: ConcurrentHashMap<String, RateLimitEntry>

    private val rateLimitWindowMs = 1000L
    private val rateLimitMaxRequests = 10

    @Before
    fun setup() {
        rateLimitMap = ConcurrentHashMap()
    }

    private fun checkRateLimit(callerPackage: String): Boolean {
        val now = System.currentTimeMillis()
        val entry = rateLimitMap.compute(callerPackage) { _, existing ->
            if (existing == null || now - existing.windowStart >= rateLimitWindowMs) {
                RateLimitEntry(1, now)
            } else {
                existing.count++
                existing
            }
        }
        return entry != null && entry.count <= rateLimitMaxRequests
    }

    @Test
    fun `first request is allowed`() {
        assertTrue(checkRateLimit("com.test.app"))
    }

    @Test
    fun `requests within limit are allowed`() {
        val caller = "com.test.app"
        for (i in 1..rateLimitMaxRequests) {
            assertTrue("Request $i should be allowed", checkRateLimit(caller))
        }
    }

    @Test
    fun `request exceeding limit is denied`() {
        val caller = "com.test.app"
        for (i in 1..rateLimitMaxRequests) {
            checkRateLimit(caller)
        }
        assertFalse(checkRateLimit(caller))
    }

    @Test
    fun `different callers have separate limits`() {
        val caller1 = "com.test.app1"
        val caller2 = "com.test.app2"

        for (i in 1..rateLimitMaxRequests) {
            checkRateLimit(caller1)
        }
        assertFalse(checkRateLimit(caller1))
        assertTrue(checkRateLimit(caller2))
    }

    @Test
    fun `rate limit resets after window`() {
        val caller = "com.test.app"
        for (i in 1..rateLimitMaxRequests) {
            checkRateLimit(caller)
        }
        assertFalse(checkRateLimit(caller))

        rateLimitMap[caller]?.windowStart = System.currentTimeMillis() - rateLimitWindowMs - 1

        assertTrue(checkRateLimit(caller))
    }

    @Test
    fun `concurrent requests from same caller are tracked`() {
        val caller = "com.test.app"
        val threads = (1..rateLimitMaxRequests + 5).map {
            Thread { checkRateLimit(caller) }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }

        val entry = rateLimitMap[caller]
        assertTrue(entry != null && entry.count > rateLimitMaxRequests)
    }

    @Test
    fun `empty caller package is handled`() {
        assertTrue(checkRateLimit(""))
    }

    @Test
    fun `special characters in caller package are handled`() {
        assertTrue(checkRateLimit("com.test.app_123-special"))
    }
}
