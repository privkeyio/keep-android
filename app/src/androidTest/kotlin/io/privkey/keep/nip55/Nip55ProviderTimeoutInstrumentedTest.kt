package io.privkey.keep.nip55

import android.database.Cursor
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.NoHandle
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.Semaphore

/**
 * Deterministic coverage of the provider's timed-out branches (gh #389, deferred from #374).
 *
 * The cross-process suite ([Nip55CrossProcessRequestInstrumentedTest]) cannot reach the
 * runWithTimeout -> rejectedCursor mapping without injecting real wall-clock delay. Here the
 * SAME null-result branch is driven by draining the provider's concurrentRequestSemaphore:
 * runWithTimeout fails its tryAcquire() and returns null immediately, which is the exact
 * condition ("timeout or concurrency limit") that logs deny_velocity_timeout / deny_timeout
 * and returns the rejected cursor. No sleeps, no flakiness.
 */
@RunWith(AndroidJUnit4::class)
class Nip55ProviderTimeoutInstrumentedTest {

    private lateinit var database: Nip55Database
    private lateinit var store: PermissionStore
    private lateinit var provider: Nip55ContentProvider

    private val app: KeepMobileApp get() = ApplicationProvider.getApplicationContext()
    private val pkg = "io.privkey.keeptest.timeoutcaller"
    private val content = """{"kind":1,"content":"gm","tags":[]}"""

    @Before
    fun setup() {
        database = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            Nip55Database::class.java
        ).allowMainThreadQueries().build()
        store = PermissionStore(database)
        provider = Nip55ContentProvider()
    }

    @After
    fun teardown() {
        database.close()
    }

    private fun semaphore(): Semaphore {
        val f = Nip55ContentProvider::class.java.getDeclaredField("concurrentRequestSemaphore")
        f.isAccessible = true
        return f.get(provider) as Semaphore
    }

    private fun invokeVelocity(): Cursor? {
        val m = Nip55ContentProvider::class.java.declaredMethods.first { it.name == "checkVelocityLimits" }
        m.isAccessible = true
        return m.invoke(provider, store, pkg, Nip55RequestType.SIGN_EVENT, 1) as Cursor?
    }

    private fun invokePermissionWithRisk(): Cursor? {
        val handler = Nip55Handler(NoHandle)
        val m = Nip55ContentProvider::class.java.declaredMethods.first { it.name == "checkPermissionWithRisk" }
        m.isAccessible = true
        return m.invoke(
            provider, store, handler, app, pkg, Nip55RequestType.SIGN_EVENT,
            content, null, 1, null, null, null
        ) as Cursor?
    }

    private fun assertRejected(cursor: Cursor?) {
        assertTrue("timed-out branch must return a cursor", cursor != null)
        assertEquals(listOf("rejected"), cursor!!.columnNames.toList())
        assertTrue(cursor.moveToFirst())
        assertEquals("true", cursor.getString(0))
    }

    @Test
    fun velocityCheck_timedOut_mapsToRejectedCursor() {
        semaphore().drainPermits()
        assertRejected(invokeVelocity())
    }

    @Test
    fun permissionCheck_timedOut_mapsToRejectedCursor() {
        semaphore().drainPermits()
        assertRejected(invokePermissionWithRisk())
    }

    @Test
    fun velocityCheck_withPermits_doesNotRejectAsTimeout() {
        // Contrast: permits available -> runWithTimeout runs the real store check, which
        // allows a fresh caller, so no rejected cursor is produced. Proves the rejection in
        // the other cases comes from the timed-out branch, not from stored velocity data.
        assertNull(invokeVelocity())
    }
}
