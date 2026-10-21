package io.privkey.keep.nip46

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.nip46ApprovalTimeoutSecs
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The approval wait has to end before the core's own backstop on the same wait. If it
 * did not, the core could deny a request at its deadline while the user, a moment later,
 * saw their approval accepted.
 */
@RunWith(AndroidJUnit4::class)
class ApprovalTimeoutTest {

    @Test
    fun theWaitEndsWellBeforeTheCoreBackstop() {
        val coreMs = nip46ApprovalTimeoutSecs().toLong() * 1000L
        assertTrue(
            "the margin is what lets this side decide first",
            BunkerService.APPROVAL_TIMEOUT_MS <= coreMs - MIN_MARGIN_MS
        )
    }

    private companion object {
        const val MIN_MARGIN_MS = 5_000L
    }
}
