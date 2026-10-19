package io.privkey.keep.nip46

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The approval wait has to end before the core's own backstop on the same wait. If it
 * did not, the core could deny a request at its deadline while the user, a moment later,
 * saw their approval accepted.
 */
class ApprovalTimeoutTest {

    @Test
    fun theWaitEndsWellBeforeTheCoreBackstop() {
        assertTrue(
            "the margin is what lets this side decide first",
            BunkerService.APPROVAL_TIMEOUT_MS <= CORE_APPROVAL_TIMEOUT_MS - MIN_MARGIN_MS
        )
    }

    private companion object {
        // APPROVAL_TIMEOUT in the core's nip46.rs, which is not exported.
        const val CORE_APPROVAL_TIMEOUT_MS = 60_000L
        const val MIN_MARGIN_MS = 5_000L
    }
}
