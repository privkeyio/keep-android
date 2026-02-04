package io.privkey.keep.nip55

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PermissionDatabaseIntegrationTest {

    private lateinit var database: Nip55Database
    private lateinit var permissionDao: Nip55PermissionDao
    private lateinit var auditLogDao: Nip55AuditLogDao
    private lateinit var appSettingsDao: Nip55AppSettingsDao

    @Before
    fun setup() {
        database = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            Nip55Database::class.java
        ).allowMainThreadQueries().build()
        permissionDao = database.permissionDao()
        auditLogDao = database.auditLogDao()
        appSettingsDao = database.appSettingsDao()
    }

    @After
    fun teardown() {
        database.close()
    }

    @Test
    fun insertAndRetrievePermission() = runBlocking {
        val permission = Nip55Permission(
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = null,
            createdAt = System.currentTimeMillis()
        )
        permissionDao.insertPermission(permission)

        val retrieved = permissionDao.getPermission("com.test.app", "SIGN_EVENT", 1)
        assertNotNull(retrieved)
        assertEquals("com.test.app", retrieved?.callerPackage)
        assertEquals("SIGN_EVENT", retrieved?.requestType)
        assertEquals(1, retrieved?.eventKind)
        assertEquals("allow", retrieved?.decision)
    }

    @Test
    fun getPermissionWithGenericEventKind() = runBlocking {
        val permission = Nip55Permission(
            callerPackage = "com.test.app",
            requestType = "GET_PUBLIC_KEY",
            eventKind = EVENT_KIND_GENERIC,
            decision = "allow",
            expiresAt = null,
            createdAt = System.currentTimeMillis()
        )
        permissionDao.insertPermission(permission)

        val retrieved = permissionDao.getPermission("com.test.app", "GET_PUBLIC_KEY", EVENT_KIND_GENERIC)
        assertNotNull(retrieved)
        assertEquals(EVENT_KIND_GENERIC, retrieved?.eventKind)
        assertNull(retrieved?.eventKindOrNull)
    }

    @Test
    fun updateExistingPermission() = runBlocking {
        val permission = Nip55Permission(
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = null,
            createdAt = System.currentTimeMillis()
        )
        permissionDao.insertPermission(permission)

        val updated = permission.copy(decision = "deny")
        permissionDao.insertPermission(updated)

        val retrieved = permissionDao.getPermission("com.test.app", "SIGN_EVENT", 1)
        assertEquals("deny", retrieved?.decision)
    }

    @Test
    fun deleteExpiredPermissions() = runBlocking {
        val now = System.currentTimeMillis()
        val nowElapsed = 100000L

        val expiredByWallClock = Nip55Permission(
            callerPackage = "com.test.expired.wallclock",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = now - 1000,
            createdAt = now - 2000
        )
        val expiredByClockManipulation = Nip55Permission(
            callerPackage = "com.test.expired.manipulation",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = now + 60000,
            createdAt = now + 120000
        )
        val expiredByMonotonicTime = Nip55Permission(
            callerPackage = "com.test.expired.monotonic",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = null,
            createdAt = now - 70000,
            createdAtElapsed = nowElapsed - 70000,
            durationMs = 60000
        )
        val expiredByElapsedRegression = Nip55Permission(
            callerPackage = "com.test.expired.elapsed_regression",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = null,
            createdAt = now,
            createdAtElapsed = nowElapsed + 50000,
            durationMs = 60000
        )
        val validByWallClock = Nip55Permission(
            callerPackage = "com.test.valid.wallclock",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = now + 60000,
            createdAt = now
        )
        val validByMonotonicTime = Nip55Permission(
            callerPackage = "com.test.valid.monotonic",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = null,
            createdAt = now,
            createdAtElapsed = nowElapsed - 10000,
            durationMs = 60000
        )
        val permanent = Nip55Permission(
            callerPackage = "com.test.permanent",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = null,
            createdAt = now
        )

        permissionDao.insertPermission(expiredByWallClock)
        permissionDao.insertPermission(expiredByClockManipulation)
        permissionDao.insertPermission(expiredByMonotonicTime)
        permissionDao.insertPermission(expiredByElapsedRegression)
        permissionDao.insertPermission(validByWallClock)
        permissionDao.insertPermission(validByMonotonicTime)
        permissionDao.insertPermission(permanent)

        permissionDao.deleteExpired(now, nowElapsed)

        assertNull(permissionDao.getPermission("com.test.expired.wallclock", "SIGN_EVENT", 1))
        assertNull(permissionDao.getPermission("com.test.expired.manipulation", "SIGN_EVENT", 1))
        assertNull(permissionDao.getPermission("com.test.expired.monotonic", "SIGN_EVENT", 1))
        assertNull(permissionDao.getPermission("com.test.expired.elapsed_regression", "SIGN_EVENT", 1))
        assertNotNull(permissionDao.getPermission("com.test.valid.wallclock", "SIGN_EVENT", 1))
        assertNotNull(permissionDao.getPermission("com.test.valid.monotonic", "SIGN_EVENT", 1))
        assertNotNull(permissionDao.getPermission("com.test.permanent", "SIGN_EVENT", 1))
    }

    @Test
    fun deleteForCaller() = runBlocking {
        val now = System.currentTimeMillis()
        permissionDao.insertPermission(Nip55Permission(
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = null,
            createdAt = now
        ))
        permissionDao.insertPermission(Nip55Permission(
            callerPackage = "com.test.app",
            requestType = "GET_PUBLIC_KEY",
            eventKind = EVENT_KIND_GENERIC,
            decision = "allow",
            expiresAt = null,
            createdAt = now
        ))
        permissionDao.insertPermission(Nip55Permission(
            callerPackage = "com.other.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = null,
            createdAt = now
        ))

        permissionDao.deleteForCaller("com.test.app")

        val all = permissionDao.getAll()
        assertEquals(1, all.size)
        assertEquals("com.other.app", all[0].callerPackage)
    }

    @Test
    fun getDistinctCallers() = runBlocking {
        val now = System.currentTimeMillis()
        listOf("com.app1", "com.app2", "com.app1", "com.app3").forEachIndexed { index, pkg ->
            permissionDao.insertPermission(Nip55Permission(
                callerPackage = pkg,
                requestType = "SIGN_EVENT",
                eventKind = index + 1,
                decision = "allow",
                expiresAt = null,
                createdAt = now
            ))
        }

        val callers = permissionDao.getDistinctCallers()
        assertEquals(3, callers.size)
        assertTrue(callers.containsAll(listOf("com.app1", "com.app2", "com.app3")))
    }

    @Test
    fun insertAndRetrieveAuditLog() = runBlocking {
        val log = Nip55AuditLog(
            timestamp = System.currentTimeMillis(),
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            wasAutomatic = true
        )
        auditLogDao.insert(log)

        val retrieved = auditLogDao.getRecent(10)
        assertEquals(1, retrieved.size)
        assertEquals("com.test.app", retrieved[0].callerPackage)
        assertTrue(retrieved[0].wasAutomatic)
    }

    @Test
    fun auditLogPagination() = runBlocking {
        val now = System.currentTimeMillis()
        repeat(25) { i ->
            auditLogDao.insert(Nip55AuditLog(
                timestamp = now - i * 1000,
                callerPackage = "com.test.app",
                requestType = "SIGN_EVENT",
                eventKind = i,
                decision = "allow",
                wasAutomatic = false
            ))
        }

        val page1 = auditLogDao.getPage(10, 0)
        val page2 = auditLogDao.getPage(10, 10)
        val page3 = auditLogDao.getPage(10, 20)

        assertEquals(10, page1.size)
        assertEquals(10, page2.size)
        assertEquals(5, page3.size)
    }

    @Test
    fun getLastUsedTime() = runBlocking {
        val now = System.currentTimeMillis()
        auditLogDao.insert(Nip55AuditLog(
            timestamp = now - 10000,
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            wasAutomatic = false
        ))
        auditLogDao.insert(Nip55AuditLog(
            timestamp = now - 5000,
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            wasAutomatic = false
        ))
        auditLogDao.insert(Nip55AuditLog(
            timestamp = now - 3000,
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "deny",
            wasAutomatic = false
        ))

        val lastUsed = auditLogDao.getLastUsedTime("com.test.app")
        assertNotNull(lastUsed)
        assertEquals(now - 5000, lastUsed)
    }

    @Test
    fun deleteOldAuditLogs() = runBlocking {
        val now = System.currentTimeMillis()
        auditLogDao.insert(Nip55AuditLog(
            timestamp = now - 100000,
            callerPackage = "com.old.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            wasAutomatic = false
        ))
        auditLogDao.insert(Nip55AuditLog(
            timestamp = now - 1000,
            callerPackage = "com.recent.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            wasAutomatic = false
        ))

        auditLogDao.deleteOlderThan(now - 50000)

        val remaining = auditLogDao.getRecent(100)
        assertEquals(1, remaining.size)
        assertEquals("com.recent.app", remaining[0].callerPackage)
    }

    @Test
    fun insertAndRetrieveAppSettings() = runBlocking {
        val settings = Nip55AppSettings(
            callerPackage = "com.test.app",
            expiresAt = System.currentTimeMillis() + 60000,
            signPolicyOverride = 1,
            createdAt = System.currentTimeMillis()
        )
        appSettingsDao.insertOrUpdate(settings)

        val retrieved = appSettingsDao.getSettings("com.test.app")
        assertNotNull(retrieved)
        assertEquals(1, retrieved?.signPolicyOverride)
    }

    @Test
    fun appSettingsExpiry() = runBlocking {
        val now = System.currentTimeMillis()
        val nowElapsed = 100000L

        appSettingsDao.insertOrUpdate(Nip55AppSettings(
            callerPackage = "com.expired.wallclock",
            expiresAt = now - 1000,
            signPolicyOverride = null,
            createdAt = now - 2000
        ))
        appSettingsDao.insertOrUpdate(Nip55AppSettings(
            callerPackage = "com.expired.manipulation",
            expiresAt = now + 60000,
            signPolicyOverride = null,
            createdAt = now + 120000
        ))
        appSettingsDao.insertOrUpdate(Nip55AppSettings(
            callerPackage = "com.expired.monotonic",
            expiresAt = null,
            signPolicyOverride = null,
            createdAt = now - 70000,
            createdAtElapsed = nowElapsed - 70000,
            durationMs = 60000
        ))
        appSettingsDao.insertOrUpdate(Nip55AppSettings(
            callerPackage = "com.expired.elapsed_regression",
            expiresAt = null,
            signPolicyOverride = null,
            createdAt = now,
            createdAtElapsed = nowElapsed + 50000,
            durationMs = 60000
        ))
        appSettingsDao.insertOrUpdate(Nip55AppSettings(
            callerPackage = "com.valid.wallclock",
            expiresAt = now + 60000,
            signPolicyOverride = null,
            createdAt = now
        ))
        appSettingsDao.insertOrUpdate(Nip55AppSettings(
            callerPackage = "com.valid.monotonic",
            expiresAt = null,
            signPolicyOverride = null,
            createdAt = now,
            createdAtElapsed = nowElapsed - 10000,
            durationMs = 60000
        ))

        val expired = appSettingsDao.getExpiredPackages(now, nowElapsed)
        assertEquals(4, expired.size)
        assertTrue(expired.contains("com.expired.wallclock"))
        assertTrue(expired.contains("com.expired.manipulation"))
        assertTrue(expired.contains("com.expired.monotonic"))
        assertTrue(expired.contains("com.expired.elapsed_regression"))

        appSettingsDao.deleteExpired(now, nowElapsed)
        assertNull(appSettingsDao.getSettings("com.expired.wallclock"))
        assertNull(appSettingsDao.getSettings("com.expired.manipulation"))
        assertNull(appSettingsDao.getSettings("com.expired.monotonic"))
        assertNull(appSettingsDao.getSettings("com.expired.elapsed_regression"))
        assertNotNull(appSettingsDao.getSettings("com.valid.wallclock"))
        assertNotNull(appSettingsDao.getSettings("com.valid.monotonic"))
    }

    @Test
    fun updateDecision() = runBlocking {
        val permission = Nip55Permission(
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = null,
            createdAt = System.currentTimeMillis()
        )
        permissionDao.insertPermission(permission)

        val inserted = permissionDao.getPermission("com.test.app", "SIGN_EVENT", 1)
        assertNotNull(inserted)

        permissionDao.updateDecision(inserted!!.id, "deny")

        val updated = permissionDao.getById(inserted.id)
        assertEquals("deny", updated?.decision)
    }

    @Test
    fun uniqueConstraintOnPermission() = runBlocking {
        val now = System.currentTimeMillis()
        permissionDao.insertPermission(Nip55Permission(
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = null,
            createdAt = now
        ))
        permissionDao.insertPermission(Nip55Permission(
            callerPackage = "com.test.app",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "deny",
            expiresAt = null,
            createdAt = now + 1000
        ))

        val all = permissionDao.getAll()
        assertEquals(1, all.size)
        assertEquals("deny", all[0].decision)
    }
}
