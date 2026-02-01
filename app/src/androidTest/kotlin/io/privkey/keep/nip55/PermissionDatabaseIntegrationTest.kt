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
    fun getPermissionWithNullEventKind() = runBlocking {
        val permission = Nip55Permission(
            callerPackage = "com.test.app",
            requestType = "GET_PUBLIC_KEY",
            eventKind = null,
            decision = "allow",
            expiresAt = null,
            createdAt = System.currentTimeMillis()
        )
        permissionDao.insertPermission(permission)

        val retrieved = permissionDao.getPermission("com.test.app", "GET_PUBLIC_KEY", null)
        assertNotNull(retrieved)
        assertNull(retrieved?.eventKind)
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
        val expired = Nip55Permission(
            callerPackage = "com.test.expired",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = now - 1000,
            createdAt = now - 2000
        )
        val valid = Nip55Permission(
            callerPackage = "com.test.valid",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = now + 60000,
            createdAt = now
        )
        val permanent = Nip55Permission(
            callerPackage = "com.test.permanent",
            requestType = "SIGN_EVENT",
            eventKind = 1,
            decision = "allow",
            expiresAt = null,
            createdAt = now
        )

        permissionDao.insertPermission(expired)
        permissionDao.insertPermission(valid)
        permissionDao.insertPermission(permanent)

        permissionDao.deleteExpired(now)

        assertNull(permissionDao.getPermission("com.test.expired", "SIGN_EVENT", 1))
        assertNotNull(permissionDao.getPermission("com.test.valid", "SIGN_EVENT", 1))
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
            eventKind = null,
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
        listOf("com.app1", "com.app2", "com.app1", "com.app3").forEach { pkg ->
            permissionDao.insertPermission(Nip55Permission(
                callerPackage = pkg,
                requestType = "SIGN_EVENT",
                eventKind = (1..100).random(),
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
        appSettingsDao.insertOrUpdate(Nip55AppSettings(
            callerPackage = "com.expired.app",
            expiresAt = now - 1000,
            signPolicyOverride = null,
            createdAt = now - 2000
        ))
        appSettingsDao.insertOrUpdate(Nip55AppSettings(
            callerPackage = "com.valid.app",
            expiresAt = now + 60000,
            signPolicyOverride = null,
            createdAt = now
        ))

        val expired = appSettingsDao.getExpiredPackages(now)
        assertEquals(1, expired.size)
        assertEquals("com.expired.app", expired[0])

        appSettingsDao.deleteExpired(now)
        assertNull(appSettingsDao.getSettings("com.expired.app"))
        assertNotNull(appSettingsDao.getSettings("com.valid.app"))
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
