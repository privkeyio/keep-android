package io.privkey.keep.nip55

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * An auto-signed request is answered without the user present, so its audit row
 * is the only record it ever happened, and the velocity and frequency inputs of
 * later decisions are counted from those same rows. The row therefore has to be
 * a condition of returning the signature, not a side effect attempted after it.
 *
 * The append runs under the provider's wall-clock bound, which answers `null`
 * for three different things: the budget running out, the block failing, and the
 * concurrency permits being exhausted. The last is the one that makes this more
 * than theory, because the permits are process-wide and few, and nothing about
 * it looks like an error: no exception is raised and nothing is logged. These
 * tests hold the permits and assert the append reports itself skipped rather
 * than quietly passing, and that no row appears when it does.
 *
 * What is not covered here, by design rather than omission: the provider refuses
 * a same-uid caller, so instrumentation cannot drive a request through it end to
 * end and the one line that turns a false into an error cursor is verified by
 * reading. The cross-process harness is where that path is exercised.
 */
@RunWith(AndroidJUnit4::class)
class AutoSignAuditRecordTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private fun store(): PermissionStore =
        (context.applicationContext as KeepMobileApp).getPermissionStore()
            ?: error("PermissionStore not initialized")

    private val released = CountDownLatch(1)
    private val occupied = CountDownLatch(PERMITS)
    private val holders = mutableListOf<Thread>()

    @After
    fun releaseThePermits() {
        released.countDown()
        holders.forEach { it.join(TimeUnit.SECONDS.toMillis(10)) }
    }

    /**
     * Occupies every permit until the test ends.
     *
     * The permits are held by blocking inside the bounded call rather than by
     * reaching into the semaphore, so what the test occupies is what a
     * concurrent request occupies.
     */
    private fun occupyThePermits(provider: Nip55ContentProvider) {
        repeat(PERMITS) {
            val holder = Thread {
                provider.runWithTimeout {
                    occupied.countDown()
                    released.await()
                    true
                }
            }
            holders.add(holder)
            holder.start()
        }
        assertTrue(
            "the permits must be occupied before the append is attempted",
            occupied.await(10, TimeUnit.SECONDS)
        )
    }

    // The case that makes the bug reachable without a fault anywhere: the append
    // is skipped for want of a permit, which raises nothing and logs nothing.
    @Test
    fun anAppendThatNeverRanReportsItselfSkipped() {
        val provider = Nip55ContentProvider()
        val before = runBlocking { store().getAuditLogCount() }
        occupyThePermits(provider)

        val recorded = provider.recordAutoSigned(store(), CALLER, Nip55RequestType.SIGN_EVENT, 1)

        assertFalse("an append that never ran must not report success", recorded)
        assertEquals(
            "and must not have written a row",
            before,
            runBlocking { store().getAuditLogCount() }
        )
    }

    // The control: with a permit free the same call records and says so, so the
    // refusal above is the permits and not the call.
    @Test
    fun anAppendThatRanReportsSuccessAndWritesTheRow() {
        val provider = Nip55ContentProvider()
        val before = runBlocking { store().getAuditLogCount() }

        val recorded = provider.recordAutoSigned(store(), CALLER, Nip55RequestType.SIGN_EVENT, 1)

        assertTrue("an append that ran must report success", recorded)
        assertEquals(
            "and must have written exactly one row",
            before + 1,
            runBlocking { store().getAuditLogCount() }
        )
    }

    private companion object {
        // Mirrors the provider's own permit count; the test fails loudly rather
        // than silently proving nothing if that ever grows, since the append
        // would then find a permit and report success.
        const val PERMITS = 4
        const val CALLER = "io.privkey.keep.test.autosign.audit"
    }
}
