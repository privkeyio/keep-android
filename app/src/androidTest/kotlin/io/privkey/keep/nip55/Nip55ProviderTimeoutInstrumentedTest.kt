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
 * Deterministic coverage of the provider's timed-out branch (gh #389, deferred from #374).
 *
 * The cross-process suite ([Nip55CrossProcessRequestInstrumentedTest]) cannot reach the
 * runWithTimeout -> rejectedCursor mapping without injecting real wall-clock delay. Here the
 * SAME null-result branch is driven by draining the provider's concurrentRequestSemaphore:
 * runWithTimeout fails its tryAcquire() and returns null immediately. The background decision
 * (decideBackgroundRequest) gathers the velocity check-and-record first, so a drained
 * semaphore surfaces as a velocity timeout, which the Rust orchestrator maps to
 * deny_velocity_timeout and the provider returns as the rejected cursor. The individual
 * per-gate timeout branches (velocity / permission lookup) are unit-tested in the orchestrator
 * (keep-mobile nip55_decision); here we assert the provider's end-to-end timeout -> rejected
 * and permits -> fall-to-UI mappings. No sleeps, no flakiness.
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

    private fun invokeDecide(): Cursor? {
        val handler = Nip55Handler(NoHandle)
        val m = Nip55ContentProvider::class.java.declaredMethods.first { it.name == "decideBackgroundRequest" }
        m.isAccessible = true
        return m.invoke(
            provider, app, store, handler, pkg, Nip55RequestType.SIGN_EVENT,
            content, null, 1, null
        ) as Cursor?
    }

    private fun assertRejected(cursor: Cursor?) {
        assertTrue("timed-out branch must return a cursor", cursor != null)
        assertEquals(listOf("rejected"), cursor!!.columnNames.toList())
        assertTrue(cursor.moveToFirst())
        assertEquals("true", cursor.getString(0))
    }

    @Test
    fun decision_timedOut_mapsToRejectedCursor() {
        // Drained semaphore -> the velocity check-and-record returns null -> the orchestrator
        // maps that to deny_velocity_timeout -> rejected cursor (fail closed).
        semaphore().drainPermits()
        assertRejected(invokeDecide())
    }

    @Test
    fun decision_withPermits_fallsToUi() {
        // Contrast: permits available -> a fresh caller under the default MANUAL policy has no
        // standing decision, i.e. RequireUi, which the background path returns as a null cursor.
        // Proves the rejection above comes from the timed-out branch, not from stored data.
        assertNull(invokeDecide())
    }
}
