package io.privkey.keep.nip55

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Verifies that `Nip55ContentProvider.runWithTimeout` imposes a real wall-clock
 * bound on a blocking, non-cancellable call (gh #314).
 *
 * The auto-sign path calls a blocking FFI (e.g. `SigningRateLimiter.checkAndRecord`,
 * a synchronous encrypted keystore write) with no suspension point, so
 * `withTimeoutOrNull` cannot cancel it in place. This test drives that shape with a
 * `Thread.sleep` far longer than `OPERATION_TIMEOUT_MS` (5s) and asserts the call
 * fails closed (`null`) well within the budget rather than waiting for the blocking
 * work. Against the previous implementation (which ran the blocking call inside the
 * timeout scope) this would only return after the full ~15s sleep.
 */
@RunWith(AndroidJUnit4::class)
class Nip55RunWithTimeoutInstrumentedTest {

    @Test
    fun runWithTimeout_failsClosedWithinTheBudget_onABlockingCall() {
        val provider = Nip55ContentProvider()
        val start = System.currentTimeMillis()
        val result: String? = provider.runWithTimeout {
            // Blocking, no suspension point -- stands in for a stuck FFI call.
            Thread.sleep(15_000)
            "must-not-be-returned"
        }
        val elapsedMs = System.currentTimeMillis() - start

        assertNull("a blocking call over the budget must fail closed (null)", result)
        assertTrue(
            "runWithTimeout must return within its wall-clock budget, not wait for the " +
                "blocking call (elapsed=${elapsedMs}ms, budget=5000ms)",
            elapsedMs < 10_000,
        )
    }
}
