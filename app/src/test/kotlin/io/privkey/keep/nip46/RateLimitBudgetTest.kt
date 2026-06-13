package io.privkey.keep.nip46

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class RateLimitBudgetTest {

    @Test
    fun connectUsesConnectBudget() {
        assertEquals(
            RateLimitBudget.CONNECT,
            rateLimitBudgetFor(isConnectRequest = true)
        )
    }

    @Test
    fun nonConnectUsesSigningBudget() {
        assertEquals(
            RateLimitBudget.SIGNING,
            rateLimitBudgetFor(isConnectRequest = false)
        )
    }

    @Test
    fun connectAndSigningDrawFromDifferentBudgets() {
        assertNotEquals(
            rateLimitBudgetFor(isConnectRequest = true),
            rateLimitBudgetFor(isConnectRequest = false)
        )
    }
}
