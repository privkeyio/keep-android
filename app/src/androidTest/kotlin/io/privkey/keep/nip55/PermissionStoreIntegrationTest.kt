package io.privkey.keep.nip55

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
}
