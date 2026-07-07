package io.privkey.keep.nip55

import android.os.SystemClock
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device regression coverage for the pinned Rust NIP-55 expiry/anti-tamper policy
 * (keep-mobile/src/nip55_policy.rs, gh #305).
 *
 * PR #302 moved clock-manipulation / reboot / wall-clock-fallback expiry out of Kotlin
 * into the uniffi policy, deleting the JVM PermissionModelTest edge cases. These paths
 * were left uncovered on Android. [PermissionStore.getPermissionDecision] reads the
 * REAL SystemClock.elapsedRealtime()/System.currentTimeMillis() and cannot be given a
 * fake "now"; instead each case persists a permission row whose stored
 * createdAt/createdAtElapsed/expiresAt/durationMs are positioned RELATIVE to the real
 * clocks to drive one anti-tamper branch, paired with a healthy control row that must
 * still resolve ALLOW. A regression in the Rust policy fails the corresponding assertion.
 */
@RunWith(AndroidJUnit4::class)
class PermissionExpiryRegressionInstrumentedTest {

    private lateinit var database: Nip55Database
    private lateinit var store: PermissionStore

    @Before
    fun setup() {
        database = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            Nip55Database::class.java
        ).allowMainThreadQueries().build()
        store = PermissionStore(database)
    }

    @After
    fun teardown() {
        database.close()
    }

    // Branch (a): wall-clock moved backwards relative to createdAt. A row whose createdAt
    // sits in the future (as if the wall clock were rewound below its creation time) must
    // read expired even though its expiresAt is still in the future.
    @Test
    fun wallClockManipulationBackwardsReadsExpired() = runBlocking {
        val dao = database.permissionDao()
        val now = System.currentTimeMillis()

        dao.insertPermission(Nip55Permission(
            callerPackage = "com.clock.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = now + DAY_MS,
            createdAt = now + DAY_MS,
            createdAtElapsed = 0,
            durationMs = null
        ))
        dao.insertPermission(Nip55Permission(
            callerPackage = "com.clock.app",
            requestType = "SIGN_EVENT",
            eventKind = 2,
            decision = "allow",
            expiresAt = now + DAY_MS,
            createdAt = now - DAY_MS,
            createdAtElapsed = 0,
            durationMs = null
        ))

        assertNull(
            "future createdAt (wall clock rewound) must fail closed",
            store.getPermissionDecision("com.clock.app", Nip55RequestType.SIGN_EVENT, 1)
        )
        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision("com.clock.app", Nip55RequestType.SIGN_EVENT, 2)
        )
    }

    // Branch (b): reboot / monotonic-elapsed regression. A row whose createdAtElapsed sits
    // above the current elapsedRealtime (as after a reboot reset the monotonic clock below
    // the stamp) must read expired even though its wall-clock lifetime is unexpired.
    @Test
    fun elapsedRealtimeRewindReadsExpired() = runBlocking {
        val dao = database.permissionDao()
        val now = System.currentTimeMillis()
        val nowElapsed = SystemClock.elapsedRealtime()

        dao.insertPermission(Nip55Permission(
            callerPackage = "com.reboot.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = now + HOUR_MS,
            createdAt = now,
            createdAtElapsed = nowElapsed + DAY_MS,
            durationMs = HOUR_MS
        ))
        dao.insertPermission(Nip55Permission(
            callerPackage = "com.reboot.app",
            requestType = "SIGN_EVENT",
            eventKind = 2,
            decision = "allow",
            expiresAt = now + HOUR_MS,
            createdAt = now,
            createdAtElapsed = nowElapsed,
            durationMs = HOUR_MS
        ))

        assertNull(
            "elapsedRealtime below createdAtElapsed (reboot) must fail closed",
            store.getPermissionDecision("com.reboot.app", Nip55RequestType.SIGN_EVENT, 1)
        )
        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision("com.reboot.app", Nip55RequestType.SIGN_EVENT, 2)
        )
    }

    // Branch (c): legacy row with createdAtElapsed == 0 falls back to the wall clock. The
    // expired legacy row (createdAt + durationMs already in the past) must read expired;
    // the fresh legacy row must still resolve ALLOW.
    @Test
    fun legacyZeroElapsedFallsBackToWallClock() = runBlocking {
        val dao = database.permissionDao()
        val now = System.currentTimeMillis()

        dao.insertPermission(Nip55Permission(
            callerPackage = "com.legacy.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = null,
            createdAt = now - 2 * HOUR_MS,
            createdAtElapsed = 0,
            durationMs = HOUR_MS
        ))
        // Back-dated an hour with a day-long lifetime so the wall-fallback branch has margin
        // on both sides: a backward NTP step can't drive now below createdAt (fail-closed),
        // and the createdAt + durationMs expiry stays comfortably in the future.
        dao.insertPermission(Nip55Permission(
            callerPackage = "com.legacy.app",
            requestType = "SIGN_EVENT",
            eventKind = 2,
            decision = "allow",
            expiresAt = null,
            createdAt = now - HOUR_MS,
            createdAtElapsed = 0,
            durationMs = DAY_MS
        ))

        assertNull(
            "expired legacy row must resolve via wall-clock fallback",
            store.getPermissionDecision("com.legacy.app", Nip55RequestType.SIGN_EVENT, 1)
        )
        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision("com.legacy.app", Nip55RequestType.SIGN_EVENT, 2)
        )
    }

    // Branch (d): ordinary (non-tamper) monotonic-lifetime expiry. A row on the elapsed
    // branch (createdAtElapsed > 0) whose lifetime has run out must read expired; the paired
    // fresh row must still resolve ALLOW. This is the common expiry path a Rust regression
    // could silently collapse while the tamper branches still pass.
    @Test
    fun elapsedDurationLifetimeExpiryReadsExpired() = runBlocking {
        val dao = database.permissionDao()
        val now = System.currentTimeMillis()
        val nowElapsed = SystemClock.elapsedRealtime()

        // Stamped near boot (createdAtElapsed = 1 keeps it on the monotonic branch regardless
        // of device uptime) with a 1 ms lifetime; the real elapsedRealtime is always far past
        // it, so the elapsed comparison expires this row before expiresAt is ever consulted.
        dao.insertPermission(Nip55Permission(
            callerPackage = "com.elapsed.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = now + HOUR_MS,
            createdAt = now,
            createdAtElapsed = 1,
            durationMs = 1
        ))
        dao.insertPermission(Nip55Permission(
            callerPackage = "com.elapsed.app",
            requestType = "SIGN_EVENT",
            eventKind = 2,
            decision = "allow",
            expiresAt = now + HOUR_MS,
            createdAt = now,
            createdAtElapsed = nowElapsed,
            durationMs = HOUR_MS
        ))

        assertNull(
            "elapsed monotonic lifetime exceeded must read expired",
            store.getPermissionDecision("com.elapsed.app", Nip55RequestType.SIGN_EVENT, 1)
        )
        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision("com.elapsed.app", Nip55RequestType.SIGN_EVENT, 2)
        )
    }

    private companion object {
        const val HOUR_MS = 60 * 60 * 1000L
        const val DAY_MS = 24 * HOUR_MS
    }
}
