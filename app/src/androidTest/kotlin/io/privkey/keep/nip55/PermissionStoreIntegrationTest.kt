package io.privkey.keep.nip55

import android.os.SystemClock
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PermissionStoreIntegrationTest {

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

    @Test
    fun grantAndRetrievePermission() = runBlocking {
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = 1,
            duration = PermissionDuration.FOREVER
        )

        val decision = store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, 1)
        assertEquals(PermissionDecision.ALLOW, decision)
    }

    @Test
    fun relaySpecificGrantDoesNotLeakToOtherRelays() = runBlocking {
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = KIND_NIP42_AUTH,
            duration = PermissionDuration.FOREVER,
            relay = "relay.a.example.com"
        )

        // The granted relay resolves; a different relay does not.
        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, KIND_NIP42_AUTH, "relay.a.example.com")
        )
        assertNull(
            store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, KIND_NIP42_AUTH, "relay.b.example.com")
        )
    }

    @Test
    fun relayNoneGrantDoesNotAutoApproveValidRelay() = runBlocking {
        // A 22242 grant stored with no relay (e.g. a malformed event whose relay could
        // not be extracted) must NOT match a well-formed request for a real relay; it is
        // fail-closed and only matches an equally relay-less request.
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = KIND_NIP42_AUTH,
            duration = PermissionDuration.FOREVER,
            relay = RELAY_NONE
        )

        assertNull(
            store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, KIND_NIP42_AUTH, "relay.real.example.com")
        )
        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, KIND_NIP42_AUTH, RELAY_NONE)
        )
    }

    @Test
    fun wildcardRelayGrantCoversAllRelays() = runBlocking {
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = KIND_NIP42_AUTH,
            duration = PermissionDuration.FOREVER,
            relay = RELAY_WILDCARD
        )

        // Any relay resolves to the wildcard grant.
        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, KIND_NIP42_AUTH, "relay.a.example.com")
        )
        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, KIND_NIP42_AUTH, "relay.b.example.com")
        )
    }

    @Test
    fun relaySpecificGrantTakesPrecedenceOverWildcard() = runBlocking {
        // Wildcard allows everything, but a relay-specific DENY must win for that relay.
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = KIND_NIP42_AUTH,
            duration = PermissionDuration.FOREVER,
            relay = RELAY_WILDCARD
        )
        store.denyPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = KIND_NIP42_AUTH,
            duration = PermissionDuration.FOREVER,
            relay = "relay.blocked.example.com"
        )

        assertEquals(
            PermissionDecision.DENY,
            store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, KIND_NIP42_AUTH, "relay.blocked.example.com")
        )
        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, KIND_NIP42_AUTH, "relay.other.example.com")
        )
    }

    @Test
    fun rememberedRejectAtWildcardOverridesWildcardAllow() = runBlocking {
        // "Deny & remember" with the all-relays scope must override an existing wildcard
        // ALLOW (same unique key -> REPLACE), so the remembered reject actually applies.
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = KIND_NIP42_AUTH,
            duration = PermissionDuration.FOREVER,
            relay = RELAY_WILDCARD
        )
        store.denyPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = KIND_NIP42_AUTH,
            duration = PermissionDuration.FOREVER,
            relay = RELAY_WILDCARD
        )

        assertEquals(
            PermissionDecision.DENY,
            store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, KIND_NIP42_AUTH, "relay.any.example.com")
        )
    }

    @Test
    fun rememberedRejectAtSpecificRelayOnlyBlocksThatRelay() = runBlocking {
        // A specific-relay reject overrides only that relay's grant; other relays still
        // resolve via the wildcard ALLOW.
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = KIND_NIP42_AUTH,
            duration = PermissionDuration.FOREVER,
            relay = RELAY_WILDCARD
        )
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = KIND_NIP42_AUTH,
            duration = PermissionDuration.FOREVER,
            relay = "relay.a.example.com"
        )
        store.denyPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = KIND_NIP42_AUTH,
            duration = PermissionDuration.FOREVER,
            relay = "relay.a.example.com"
        )

        assertEquals(
            PermissionDecision.DENY,
            store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, KIND_NIP42_AUTH, "relay.a.example.com")
        )
        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, KIND_NIP42_AUTH, "relay.b.example.com")
        )
    }

    @Test
    fun expiredRelaySpecificGrantFallsBackToValidWildcard() = runBlocking {
        val dao = database.permissionDao()
        val now = System.currentTimeMillis()
        val nowElapsed = SystemClock.elapsedRealtime()

        // An expired relay-specific row must NOT shadow a still-valid wildcard ALLOW.
        dao.insertPermission(Nip55Permission(
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = KIND_NIP42_AUTH,
            relay = "relay.a.example.com",
            decision = "allow",
            expiresAt = now - 59_000,
            createdAt = now - 60_000,
            createdAtElapsed = nowElapsed - 60_000,
            durationMs = 1_000
        ))
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = KIND_NIP42_AUTH,
            duration = PermissionDuration.FOREVER,
            relay = RELAY_WILDCARD
        )

        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, KIND_NIP42_AUTH, "relay.a.example.com")
        )
    }

    @Test
    fun denyAndRetrievePermission() = runBlocking {
        store.denyPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = 1,
            duration = PermissionDuration.FOREVER
        )

        val decision = store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, 1)
        assertEquals(PermissionDecision.DENY, decision)
    }

    @Test
    fun justThisTimeDoesNotPersist() = runBlocking {
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = 1,
            duration = PermissionDuration.JUST_THIS_TIME
        )

        val decision = store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, 1)
        assertNull(decision)
    }

    @Test
    fun genericPermissionFallback() = runBlocking {
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = null,
            duration = PermissionDuration.FOREVER
        )

        val decision = store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, 1)
        assertEquals(PermissionDecision.ALLOW, decision)
    }

    @Test
    fun sensitiveKindDoesNotFallbackToGeneric() = runBlocking {
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = null,
            duration = PermissionDuration.FOREVER
        )

        val decision = store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, 4)
        assertNull(decision)
    }

    @Test
    fun sensitiveKindLimitsForeverDuration() = runBlocking {
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = 4,
            duration = PermissionDuration.FOREVER
        )

        val permissions = store.getAllPermissions()
        assertEquals(1, permissions.size)
        assertNotNull(permissions[0].expiresAt)
    }

    @Test
    fun revokeAllPermissionsForCaller() = runBlocking {
        store.grantPermission("com.test.app", Nip55RequestType.SIGN_EVENT, 1, PermissionDuration.FOREVER)
        store.grantPermission("com.test.app", Nip55RequestType.GET_PUBLIC_KEY, null, PermissionDuration.FOREVER)
        store.grantPermission("com.other.app", Nip55RequestType.SIGN_EVENT, 1, PermissionDuration.FOREVER)

        store.revokePermission("com.test.app")

        assertNull(store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, 1))
        assertNull(store.getPermissionDecision("com.test.app", Nip55RequestType.GET_PUBLIC_KEY, null))
        assertEquals(PermissionDecision.ALLOW, store.getPermissionDecision("com.other.app", Nip55RequestType.SIGN_EVENT, 1))
    }

    @Test
    fun revokeSpecificPermission() = runBlocking {
        store.grantPermission("com.test.app", Nip55RequestType.SIGN_EVENT, 1, PermissionDuration.FOREVER)
        store.grantPermission("com.test.app", Nip55RequestType.SIGN_EVENT, 7, PermissionDuration.FOREVER)

        store.revokePermission("com.test.app", Nip55RequestType.SIGN_EVENT, 1)

        assertNull(store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, 1))
        assertEquals(PermissionDecision.ALLOW, store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, 7))
    }

    @Test
    fun logOperationCreatesAuditEntry() = runBlocking {
        store.logOperation(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = 1,
            decision = "allow",
            wasAutomatic = true
        )

        val logs = store.getAuditLog(10)
        assertEquals(1, logs.size)
        assertEquals("com.test.app", logs[0].callerPackage)
        assertTrue(logs[0].wasAutomatic)
    }

    @Test
    fun connectedAppsReturnsCorrectInfo() = runBlocking {
        store.grantPermission("com.test.app", Nip55RequestType.SIGN_EVENT, 1, PermissionDuration.FOREVER)
        store.grantPermission("com.test.app", Nip55RequestType.GET_PUBLIC_KEY, null, PermissionDuration.FOREVER)
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", false)

        val apps = store.getConnectedApps()
        assertEquals(1, apps.size)
        assertEquals("com.test.app", apps[0].packageName)
        assertEquals(2, apps[0].permissionCount)
        assertNotNull(apps[0].lastUsedTime)
    }

    @Test
    fun appExpiryTracking() = runBlocking {
        store.setAppExpiry("com.test.app", AppExpiryDuration.FIVE_MINUTES)

        val settings = store.getAppSettings("com.test.app")
        assertNotNull(settings)
        assertNotNull(settings?.expiresAt)

        assertFalse(store.isAppExpired("com.test.app"))
    }

    @Test
    fun cleanupExpiredRemovesOldPermissions() = runBlocking {
        val dao = database.permissionDao()
        val now = System.currentTimeMillis()

        dao.insertPermission(Nip55Permission(
            callerPackage = "com.expired.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = now - 1000,
            createdAt = now - 2000
        ))

        store.cleanupExpired()

        assertNull(store.getPermissionDecision("com.expired.app", Nip55RequestType.SIGN_EVENT, 1))
    }

    @Test
    fun setPermissionToAsk() = runBlocking {
        store.setPermissionToAsk("com.test.app", Nip55RequestType.SIGN_EVENT, 1)

        val decision = store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, 1)
        assertEquals(PermissionDecision.ASK, decision)
    }

    @Test
    fun updatePermissionDecision() = runBlocking {
        store.grantPermission("com.test.app", Nip55RequestType.SIGN_EVENT, 1, PermissionDuration.FOREVER)

        val permissions = store.getPermissionsForCaller("com.test.app")
        assertEquals(1, permissions.size)

        store.updatePermissionDecision(
            permissions[0].id,
            PermissionDecision.DENY,
            "com.test.app",
            Nip55RequestType.SIGN_EVENT,
            1
        )

        val updated = store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, 1)
        assertEquals(PermissionDecision.DENY, updated)
    }

    @Test
    fun appSignPolicyOverride() = runBlocking {
        assertNull(store.getAppSignPolicyOverride("com.test.app"))

        store.setAppSignPolicyOverride("com.test.app", 2)

        assertEquals(2, store.getAppSignPolicyOverride("com.test.app"))

        store.setAppSignPolicyOverride("com.test.app", null)
        assertNull(store.getAppSignPolicyOverride("com.test.app"))
    }

    @Test
    fun distinctCallersFromPermissions() = runBlocking {
        store.grantPermission("com.app1", Nip55RequestType.SIGN_EVENT, 1, PermissionDuration.FOREVER)
        store.grantPermission("com.app2", Nip55RequestType.SIGN_EVENT, 1, PermissionDuration.FOREVER)
        store.grantPermission("com.app1", Nip55RequestType.GET_PUBLIC_KEY, null, PermissionDuration.FOREVER)

        val callers = store.getDistinctPermissionCallers()
        assertEquals(2, callers.size)
        assertTrue(callers.contains("com.app1"))
        assertTrue(callers.contains("com.app2"))
    }

    @Test
    fun auditLogPagination() = runBlocking {
        repeat(25) { i ->
            store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, i, "allow", false)
        }

        val page1 = store.getAuditLogPage(10, 0)
        val page2 = store.getAuditLogPage(10, 10)
        val page3 = store.getAuditLogPage(10, 20)

        assertEquals(10, page1.size)
        assertEquals(10, page2.size)
        assertEquals(5, page3.size)
    }

    @Test
    fun revokeAllForApp() = runBlocking {
        store.grantPermission("com.test.app", Nip55RequestType.SIGN_EVENT, 1, PermissionDuration.FOREVER)
        store.grantPermission("com.test.app", Nip55RequestType.SIGN_EVENT, 7, PermissionDuration.FOREVER)
        store.grantPermission("com.test.app", Nip55RequestType.GET_PUBLIC_KEY, null, PermissionDuration.FOREVER)

        store.revokeAllForApp("com.test.app")

        val permissions = store.getPermissionsForCaller("com.test.app")
        assertEquals(0, permissions.size)
    }

    @Test
    fun lastUsedTimeForPermission() = runBlocking {
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", false)
        Thread.sleep(10)
        val laterTime = System.currentTimeMillis()
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", false)

        val lastUsed = store.getLastUsedTimeForPermission("com.test.app", "SIGN_EVENT", 1)
        assertNotNull(lastUsed)
        assertTrue(lastUsed!! >= laterTime - 100)
    }

    @Test
    fun getPublicKeyPermissionType() = runBlocking {
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.GET_PUBLIC_KEY,
            eventKind = null,
            duration = PermissionDuration.FOREVER
        )

        val decision = store.getPermissionDecision("com.test.app", Nip55RequestType.GET_PUBLIC_KEY, null)
        assertEquals(PermissionDecision.ALLOW, decision)
    }

    @Test
    fun nip44EncryptPermissionType() = runBlocking {
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.NIP44_ENCRYPT,
            eventKind = null,
            duration = PermissionDuration.FOREVER
        )

        val decision = store.getPermissionDecision("com.test.app", Nip55RequestType.NIP44_ENCRYPT, null)
        assertEquals(PermissionDecision.ALLOW, decision)
    }

    @Test
    fun nip44DecryptPermissionType() = runBlocking {
        store.grantPermission(
            callerPackage = "com.test.app",
            requestType = Nip55RequestType.NIP44_DECRYPT,
            eventKind = null,
            duration = PermissionDuration.FOREVER
        )

        val decision = store.getPermissionDecision("com.test.app", Nip55RequestType.NIP44_DECRYPT, null)
        assertEquals(PermissionDecision.ALLOW, decision)
    }

    @Test
    fun flippingADenyForeverToAllowClampsASensitiveKind() = runBlocking {
        // A deny is not clamped, which is correct, so this is how an unbounded row
        // for a sensitive kind comes to exist. Flipping the decision alone would
        // turn it into an auto-approve with no expiry, which no grant through the
        // prompt can produce.
        store.denyPermission("com.test.app", Nip55RequestType.SIGN_EVENT, SENSITIVE_KIND, PermissionDuration.FOREVER)
        val row = store.getPermissionsForCaller("com.test.app").single()
        assertNull("precondition: the deny row is unbounded", row.expiresAt)
        assertNull("precondition: the deny row is unbounded", row.durationMs)

        store.updatePermissionDecision(
            row.id,
            PermissionDecision.ALLOW,
            "com.test.app",
            Nip55RequestType.SIGN_EVENT,
            SENSITIVE_KIND
        )

        val updated = store.getPermissionsForCaller("com.test.app").single()
        assertEquals(PermissionDecision.ALLOW.toString(), updated.decision)
        assertEquals(
            "a sensitive-kind allow must carry the one-day clamp",
            DAY_MS,
            updated.durationMs
        )
        assertNotNull("the clamped row must also carry a wall-clock bound", updated.expiresAt)
        assertTrue("the clamped row must be timed from the flip", updated.createdAtElapsed > 0)
    }

    @Test
    fun flippingADenyForeverToAllowLeavesANonSensitiveKindUnbounded() = runBlocking {
        // The clamp is only about sensitive kinds; an ordinary kind keeps the
        // forever the user chose.
        store.denyPermission("com.test.app", Nip55RequestType.SIGN_EVENT, PLAIN_KIND, PermissionDuration.FOREVER)
        val row = store.getPermissionsForCaller("com.test.app").single()

        store.updatePermissionDecision(
            row.id,
            PermissionDecision.ALLOW,
            "com.test.app",
            Nip55RequestType.SIGN_EVENT,
            PLAIN_KIND
        )

        val updated = store.getPermissionsForCaller("com.test.app").single()
        assertEquals(PermissionDecision.ALLOW.toString(), updated.decision)
        assertNull(updated.durationMs)
        assertNull(updated.expiresAt)
    }

    @Test
    fun reTappingAllowOnALiveBoundedGrantDoesNotRestartItsClock() = runBlocking {
        // Every decision is offered on every row, so allow is tappable on a row that
        // already allows. Re-deriving the lifetime of a row that has one would hand
        // back time the row had already spent.
        store.grantPermission("com.test.app", Nip55RequestType.SIGN_EVENT, SENSITIVE_KIND, PermissionDuration.ONE_HOUR)
        val row = store.getPermissionsForCaller("com.test.app").single()

        store.updatePermissionDecision(
            row.id,
            PermissionDecision.ALLOW,
            "com.test.app",
            Nip55RequestType.SIGN_EVENT,
            SENSITIVE_KIND
        )

        val updated = store.getPermissionsForCaller("com.test.app").single()
        assertEquals(HOUR_MS, updated.durationMs)
        assertEquals(row.createdAtElapsed, updated.createdAtElapsed)
        assertEquals(row.createdAt, updated.createdAt)
    }

    @Test
    fun flippingAClampedAllowBackToDenyLeavesTheDenyStanding() = runBlocking {
        // The clamp writes a lifetime, and a refusal must not inherit it: deleteExpired
        // has no decision filter and the resolver skips an expired row whatever its
        // decision, so a bound left here would end the user's refusal and let the
        // request fall through to whatever the global policy allows.
        store.denyPermission("com.test.app", Nip55RequestType.SIGN_EVENT, SENSITIVE_KIND, PermissionDuration.FOREVER)
        val row = store.getPermissionsForCaller("com.test.app").single()
        store.updatePermissionDecision(
            row.id,
            PermissionDecision.ALLOW,
            "com.test.app",
            Nip55RequestType.SIGN_EVENT,
            SENSITIVE_KIND
        )
        assertEquals(
            "precondition: the flip to allow is clamped, so a lifetime now exists to inherit",
            DAY_MS,
            store.getPermissionsForCaller("com.test.app").single().durationMs
        )

        store.updatePermissionDecision(
            row.id,
            PermissionDecision.DENY,
            "com.test.app",
            Nip55RequestType.SIGN_EVENT,
            SENSITIVE_KIND
        )

        val updated = store.getPermissionsForCaller("com.test.app").single()
        assertEquals(PermissionDecision.DENY.toString(), updated.decision)
        assertNull("a deny must not carry a duration", updated.durationMs)
        assertNull("a deny must not carry an expiry", updated.expiresAt)
        assertFalse(
            "the refusal must still stand a day later",
            updated.isExpired(
                currentElapsed = updated.createdAtElapsed + DAY_MS + 1,
                currentTimeMillis = updated.createdAt + DAY_MS + 1
            )
        )
    }

    @Test
    fun flippingAGrantToAskDropsTheLifetimeItWouldHaveExpiredWith() = runBlocking {
        // Same rule from the other side, and the lifetime here is the grant's own
        // rather than the clamp's. An ask that expires stops blocking both the policy
        // auto-approve and the whitelisted-relay auto-accept, which is the setting the
        // user just switched on, and the flip that set it offered no duration.
        store.grantPermission("com.test.app", Nip55RequestType.SIGN_EVENT, SENSITIVE_KIND, PermissionDuration.ONE_HOUR)
        val row = store.getPermissionsForCaller("com.test.app").single()
        assertEquals("precondition: the grant is bounded", HOUR_MS, row.durationMs)

        store.updatePermissionDecision(
            row.id,
            PermissionDecision.ASK,
            "com.test.app",
            Nip55RequestType.SIGN_EVENT,
            SENSITIVE_KIND
        )

        val updated = store.getPermissionsForCaller("com.test.app").single()
        assertEquals(PermissionDecision.ASK.toString(), updated.decision)
        assertNull(updated.durationMs)
        assertNull(updated.expiresAt)
    }

    @Test
    fun aRefusalRoundTripReDerivesTheAllowAsAnUnqualifiedToggleGrant() = runBlocking {
        // The cost of clearing the lifetime above, pinned rather than left to be found:
        // the row's original hour is gone once it has been refused, so tapping allow
        // again asks for what the toggle asks for, which is forever, and gets the
        // clamp. Bounded by the clamp and reachable only by the user's own two taps.
        store.grantPermission("com.test.app", Nip55RequestType.SIGN_EVENT, SENSITIVE_KIND, PermissionDuration.ONE_HOUR)
        val row = store.getPermissionsForCaller("com.test.app").single()

        store.updatePermissionDecision(
            row.id,
            PermissionDecision.DENY,
            "com.test.app",
            Nip55RequestType.SIGN_EVENT,
            SENSITIVE_KIND
        )
        store.updatePermissionDecision(
            row.id,
            PermissionDecision.ALLOW,
            "com.test.app",
            Nip55RequestType.SIGN_EVENT,
            SENSITIVE_KIND
        )

        val updated = store.getPermissionsForCaller("com.test.app").single()
        assertEquals(DAY_MS, updated.durationMs)
    }

    @Test
    fun aClampedFlipStopsBeingAnAutoApproveOnceItsDayIsUp() = runBlocking {
        // What the clamp is for, observed through the resolution path rather than
        // through the row: the grant has to stop applying.
        store.denyPermission("com.test.app", Nip55RequestType.SIGN_EVENT, SENSITIVE_KIND, PermissionDuration.FOREVER)
        val row = store.getPermissionsForCaller("com.test.app").single()
        store.updatePermissionDecision(
            row.id,
            PermissionDecision.ALLOW,
            "com.test.app",
            Nip55RequestType.SIGN_EVENT,
            SENSITIVE_KIND
        )
        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, SENSITIVE_KIND)
        )

        val updated = store.getPermissionsForCaller("com.test.app").single()
        assertTrue(
            "the clamped grant must read as expired a day later",
            updated.isExpired(
                currentElapsed = updated.createdAtElapsed + DAY_MS + 1,
                currentTimeMillis = updated.createdAt + DAY_MS + 1
            )
        )
    }

    private companion object {
        const val SENSITIVE_KIND = 4
        const val PLAIN_KIND = 1
        const val HOUR_MS = 60 * 60 * 1000L
        const val DAY_MS = 24 * HOUR_MS
    }
}
