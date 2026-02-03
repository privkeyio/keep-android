package io.privkey.keep.nip55

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class PermissionDecisionTest {

    @Test
    fun `fromString parses allow correctly`() {
        assertEquals(PermissionDecision.ALLOW, PermissionDecision.fromString("allow"))
        assertEquals(PermissionDecision.ALLOW, PermissionDecision.fromString("ALLOW"))
        assertEquals(PermissionDecision.ALLOW, PermissionDecision.fromString("Allow"))
    }

    @Test
    fun `fromString parses deny correctly`() {
        assertEquals(PermissionDecision.DENY, PermissionDecision.fromString("deny"))
        assertEquals(PermissionDecision.DENY, PermissionDecision.fromString("DENY"))
    }

    @Test
    fun `fromString parses ask correctly`() {
        assertEquals(PermissionDecision.ASK, PermissionDecision.fromString("ask"))
        assertEquals(PermissionDecision.ASK, PermissionDecision.fromString("ASK"))
    }

    @Test
    fun `fromString defaults to DENY for unknown values`() {
        assertEquals(PermissionDecision.DENY, PermissionDecision.fromString("invalid"))
    }

    @Test
    fun `toString returns lowercase value`() {
        assertEquals("allow", PermissionDecision.ALLOW.toString())
        assertEquals("deny", PermissionDecision.DENY.toString())
        assertEquals("ask", PermissionDecision.ASK.toString())
    }
}

class Nip55PermissionTest {

    @Before
    fun setUp() {
        MonotonicClock.testTimeOverride = 100_000L
    }

    @After
    fun tearDown() {
        MonotonicClock.testTimeOverride = null
    }

    @Test
    fun `isExpired returns false when expiresAt is null`() {
        val now = MonotonicClock.now()
        val permission = Nip55Permission(
            id = 1,
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = null,
            createdAt = now
        )
        assertFalse(permission.isExpired())
    }

    @Test
    fun `isExpired returns true when expiresAt is in the past`() {
        val now = MonotonicClock.now()
        val permission = Nip55Permission(
            id = 1,
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = now - 1000,
            createdAt = now - 2000
        )
        assertTrue(permission.isExpired())
    }

    @Test
    fun `isExpired returns false when expiresAt is in the future`() {
        val now = MonotonicClock.now()
        val permission = Nip55Permission(
            id = 1,
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = now + 60000,
            createdAt = now
        )
        assertFalse(permission.isExpired())
    }

    @Test
    fun `isExpired detects clock manipulation via reboot`() {
        val now = MonotonicClock.now()
        val permission = Nip55Permission(
            id = 1,
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = now + 60000,
            createdAt = now + 120000
        )
        assertTrue(permission.isExpired())
    }

    @Test
    fun `permissionDecision returns correct enum`() {
        val now = MonotonicClock.now()
        val allowPermission = Nip55Permission(
            id = 1,
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = EVENT_KIND_GENERIC,
            decision = "allow",
            expiresAt = null,
            createdAt = now
        )
        assertEquals(PermissionDecision.ALLOW, allowPermission.permissionDecision)
        assertNull(allowPermission.eventKindOrNull)

        val denyPermission = allowPermission.copy(decision = "deny")
        assertEquals(PermissionDecision.DENY, denyPermission.permissionDecision)

        val specificKindPermission = allowPermission.copy(eventKind = 1)
        assertEquals(1, specificKindPermission.eventKindOrNull)
    }
}

class PermissionDurationTest {

    @Before
    fun setUp() {
        MonotonicClock.testTimeOverride = 100_000L
    }

    @After
    fun tearDown() {
        MonotonicClock.testTimeOverride = null
    }

    @Test
    fun `JUST_THIS_TIME does not persist`() {
        assertFalse(PermissionDuration.JUST_THIS_TIME.shouldPersist)
    }

    @Test
    fun `FOREVER persists and has null expiry`() {
        assertTrue(PermissionDuration.FOREVER.shouldPersist)
        assertNull(PermissionDuration.FOREVER.expiresAt())
    }

    @Test
    fun `timed durations have correct millis`() {
        assertEquals(60 * 1000L, PermissionDuration.ONE_MINUTE.millis)
        assertEquals(5 * 60 * 1000L, PermissionDuration.FIVE_MINUTES.millis)
        assertEquals(10 * 60 * 1000L, PermissionDuration.TEN_MINUTES.millis)
        assertEquals(60 * 60 * 1000L, PermissionDuration.ONE_HOUR.millis)
        assertEquals(24 * 60 * 60 * 1000L, PermissionDuration.ONE_DAY.millis)
    }

    @Test
    fun `expiresAt returns future timestamp for timed durations`() {
        val now = MonotonicClock.now()
        val expiry = PermissionDuration.ONE_HOUR.expiresAt()
        assertNotNull(expiry)
        assertTrue(expiry!! > now)
        assertTrue(expiry <= now + 60 * 60 * 1000L + 100)
    }
}

class FormatFunctionsTest {

    @Before
    fun setUp() {
        MonotonicClock.testTimeOverride = 100_000L
    }

    @After
    fun tearDown() {
        MonotonicClock.testTimeOverride = null
    }

    @Test
    fun `formatRequestType formats underscore-separated strings`() {
        assertEquals("Sign event", formatRequestType("SIGN_EVENT"))
        assertEquals("Get public key", formatRequestType("GET_PUBLIC_KEY"))
        assertEquals("Nip44 encrypt", formatRequestType("NIP44_ENCRYPT"))
    }

    @Test
    fun `formatRelativeTime formats recent times`() {
        val now = System.currentTimeMillis()
        assertEquals("just now", formatRelativeTime(now))
        assertEquals("just now", formatRelativeTime(now - 30_000))
    }

    @Test
    fun `formatRelativeTime formats minutes ago`() {
        val now = System.currentTimeMillis()
        assertTrue(formatRelativeTime(now - 2 * 60_000).contains("m ago"))
    }

    @Test
    fun `formatRelativeTime formats hours ago`() {
        val now = System.currentTimeMillis()
        assertTrue(formatRelativeTime(now - 2 * 60 * 60_000).contains("h ago"))
    }

    @Test
    fun `formatExpiry shows expired for past timestamps`() {
        val now = MonotonicClock.now()
        assertEquals("expired", formatExpiry(now - 1000))
    }

    @Test
    fun `formatExpiry shows remaining time for future timestamps`() {
        val now = MonotonicClock.now()
        val oneHourFromNow = now + 60 * 60 * 1000
        assertTrue(formatExpiry(oneHourFromNow).startsWith("in "))
    }
}
