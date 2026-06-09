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
    private lateinit var eventLogDao: EventLogDao

    private fun createPermission(
        callerPackage: String = "com.test.app",
        requestType: String = "SIGN_EVENT",
        eventKind: Int = 1,
        decision: String = "allow",
        expiresAt: Long? = null,
        createdAt: Long = System.currentTimeMillis(),
        createdAtElapsed: Long = 0,
        durationMs: Long? = null
    ) = Nip55Permission(
        callerPackage = callerPackage,
        requestType = requestType,
        eventKind = eventKind,
        decision = decision,
        expiresAt = expiresAt,
        createdAt = createdAt,
        createdAtElapsed = createdAtElapsed,
        durationMs = durationMs
    )

    private fun createAuditLog(
        timestamp: Long = System.currentTimeMillis(),
        callerPackage: String = "com.test.app",
        requestType: String = "SIGN_EVENT",
        eventKind: Int? = 1,
        decision: String = "allow",
        wasAutomatic: Boolean = false
    ) = Nip55AuditLog(
        timestamp = timestamp,
        callerPackage = callerPackage,
        requestType = requestType,
        eventKind = eventKind,
        decision = decision,
        wasAutomatic = wasAutomatic
    )

    private fun createAppSettings(
        callerPackage: String,
        expiresAt: Long? = null,
        signPolicyOverride: Int? = null,
        createdAt: Long = System.currentTimeMillis(),
        createdAtElapsed: Long = 0,
        durationMs: Long? = null
    ) = Nip55AppSettings(
        callerPackage = callerPackage,
        expiresAt = expiresAt,
        signPolicyOverride = signPolicyOverride,
        createdAt = createdAt,
        createdAtElapsed = createdAtElapsed,
        durationMs = durationMs
    )

    @Before
    fun setup() {
        database = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            Nip55Database::class.java
        ).allowMainThreadQueries().build()
        permissionDao = database.permissionDao()
        auditLogDao = database.auditLogDao()
        appSettingsDao = database.appSettingsDao()
        eventLogDao = database.eventLogDao()
    }

    private fun createEventLog(
        timestamp: Long = System.currentTimeMillis(),
        category: String = EventLogCategory.RELAY.name,
        level: String = EventLogLevel.INFO.name,
        source: String = "",
        message: String = "event"
    ) = EventLogEntry(
        timestamp = timestamp,
        category = category,
        level = level,
        source = source,
        message = message
    )

    @After
    fun teardown() {
        database.close()
    }

    @Test
    fun insertAndRetrievePermission() = runBlocking {
        val permission = createPermission()
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
        val permission = createPermission(requestType = "GET_PUBLIC_KEY", eventKind = EVENT_KIND_GENERIC)
        permissionDao.insertPermission(permission)

        val retrieved = permissionDao.getPermission("com.test.app", "GET_PUBLIC_KEY", EVENT_KIND_GENERIC)
        assertNotNull(retrieved)
        assertEquals(EVENT_KIND_GENERIC, retrieved?.eventKind)
        assertNull(retrieved?.eventKindOrNull)
    }

    @Test
    fun updateExistingPermission() = runBlocking {
        val permission = createPermission()
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

        val expiredByWallClock = createPermission(
            callerPackage = "com.test.expired.wallclock",
            expiresAt = now - 1000,
            createdAt = now - 2000
        )
        val expiredByClockManipulation = createPermission(
            callerPackage = "com.test.expired.manipulation",
            expiresAt = now + 60000,
            createdAt = now + 120000
        )
        val expiredByMonotonicTime = createPermission(
            callerPackage = "com.test.expired.monotonic",
            createdAt = now - 70000,
            createdAtElapsed = nowElapsed - 70000,
            durationMs = 60000
        )
        val expiredByElapsedRegression = createPermission(
            callerPackage = "com.test.expired.elapsed_regression",
            createdAt = now,
            createdAtElapsed = nowElapsed + 50000,
            durationMs = 60000
        )
        val validByWallClock = createPermission(
            callerPackage = "com.test.valid.wallclock",
            expiresAt = now + 60000,
            createdAt = now
        )
        val validByMonotonicTime = createPermission(
            callerPackage = "com.test.valid.monotonic",
            createdAt = now,
            createdAtElapsed = nowElapsed - 10000,
            durationMs = 60000
        )
        val permanent = createPermission(
            callerPackage = "com.test.permanent",
            createdAt = now
        )

        listOf(
            expiredByWallClock,
            expiredByClockManipulation,
            expiredByMonotonicTime,
            expiredByElapsedRegression,
            validByWallClock,
            validByMonotonicTime,
            permanent
        ).forEach { permissionDao.insertPermission(it) }

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
        permissionDao.insertPermission(createPermission())
        permissionDao.insertPermission(createPermission(requestType = "GET_PUBLIC_KEY", eventKind = EVENT_KIND_GENERIC))
        permissionDao.insertPermission(createPermission(callerPackage = "com.other.app"))

        permissionDao.deleteForCaller("com.test.app")

        val all = permissionDao.getAll()
        assertEquals(1, all.size)
        assertEquals("com.other.app", all[0].callerPackage)
    }

    @Test
    fun getDistinctCallers() = runBlocking {
        listOf("com.app1", "com.app2", "com.app1", "com.app3").forEachIndexed { index, pkg ->
            permissionDao.insertPermission(createPermission(callerPackage = pkg, eventKind = index + 1))
        }

        val callers = permissionDao.getDistinctCallers()
        assertEquals(3, callers.size)
        assertTrue(callers.containsAll(listOf("com.app1", "com.app2", "com.app3")))
    }

    @Test
    fun insertAndRetrieveAuditLog() = runBlocking {
        auditLogDao.insert(createAuditLog(wasAutomatic = true))

        val retrieved = auditLogDao.getRecent(10)
        assertEquals(1, retrieved.size)
        assertEquals("com.test.app", retrieved[0].callerPackage)
        assertTrue(retrieved[0].wasAutomatic)
    }

    @Test
    fun auditLogPagination() = runBlocking {
        val now = System.currentTimeMillis()
        repeat(25) { i ->
            auditLogDao.insert(createAuditLog(timestamp = now - i * 1000, eventKind = i))
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
        auditLogDao.insert(createAuditLog(timestamp = now - 10000))
        auditLogDao.insert(createAuditLog(timestamp = now - 5000))
        auditLogDao.insert(createAuditLog(timestamp = now - 3000, decision = "deny"))

        val lastUsed = auditLogDao.getLastUsedTime("com.test.app")
        assertNotNull(lastUsed)
        assertEquals(now - 5000, lastUsed)
    }

    @Test
    fun deleteOldAuditLogs() = runBlocking {
        val now = System.currentTimeMillis()
        auditLogDao.insert(createAuditLog(timestamp = now - 100000, callerPackage = "com.old.app"))
        auditLogDao.insert(createAuditLog(timestamp = now - 1000, callerPackage = "com.recent.app"))

        auditLogDao.deleteOlderThan(now - 50000)

        val remaining = auditLogDao.getRecent(100)
        assertEquals(1, remaining.size)
        assertEquals("com.recent.app", remaining[0].callerPackage)
    }

    @Test
    fun insertAndRetrieveAppSettings() = runBlocking {
        val now = System.currentTimeMillis()
        val settings = createAppSettings(
            callerPackage = "com.test.app",
            expiresAt = now + 60000,
            signPolicyOverride = 1,
            createdAt = now
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

        listOf(
            createAppSettings(
                callerPackage = "com.expired.wallclock",
                expiresAt = now - 1000,
                createdAt = now - 2000
            ),
            createAppSettings(
                callerPackage = "com.expired.manipulation",
                expiresAt = now + 60000,
                createdAt = now + 120000
            ),
            createAppSettings(
                callerPackage = "com.expired.monotonic",
                createdAt = now - 70000,
                createdAtElapsed = nowElapsed - 70000,
                durationMs = 60000
            ),
            createAppSettings(
                callerPackage = "com.expired.elapsed_regression",
                createdAt = now,
                createdAtElapsed = nowElapsed + 50000,
                durationMs = 60000
            ),
            createAppSettings(
                callerPackage = "com.valid.wallclock",
                expiresAt = now + 60000,
                createdAt = now
            ),
            createAppSettings(
                callerPackage = "com.valid.monotonic",
                createdAt = now,
                createdAtElapsed = nowElapsed - 10000,
                durationMs = 60000
            )
        ).forEach { appSettingsDao.insertOrUpdate(it) }

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
        permissionDao.insertPermission(createPermission())

        val inserted = permissionDao.getPermission("com.test.app", "SIGN_EVENT", 1)
        assertNotNull(inserted)

        permissionDao.updateDecision(inserted!!.id, "deny")

        val updated = permissionDao.getById(inserted.id)
        assertEquals("deny", updated?.decision)
    }

    @Test
    fun uniqueConstraintOnPermission() = runBlocking {
        val now = System.currentTimeMillis()
        permissionDao.insertPermission(createPermission(createdAt = now))
        permissionDao.insertPermission(createPermission(decision = "deny", createdAt = now + 1000))

        val all = permissionDao.getAll()
        assertEquals(1, all.size)
        assertEquals("deny", all[0].decision)
    }

    @Test
    fun eventLogInsertAndCount() = runBlocking {
        assertEquals(0, eventLogDao.getCount())
        eventLogDao.insert(createEventLog(message = "first"))
        eventLogDao.insert(createEventLog(message = "second"))

        assertEquals(2, eventLogDao.getCount())
        val recent = eventLogDao.getRecent(10)
        assertEquals(2, recent.size)
        assertEquals("second", recent[0].message)
        assertEquals("first", recent[1].message)
    }

    @Test
    fun eventLogKeysetPagination() = runBlocking {
        repeat(25) { i -> eventLogDao.insert(createEventLog(message = "event $i")) }

        val page1 = eventLogDao.getPageBefore(Long.MAX_VALUE, 10)
        assertEquals(10, page1.size)
        val page2 = eventLogDao.getPageBefore(page1.last().id, 10)
        assertEquals(10, page2.size)
        val page3 = eventLogDao.getPageBefore(page2.last().id, 10)
        assertEquals(5, page3.size)

        val ids = (page1 + page2 + page3).map { it.id }
        assertEquals(ids.size, ids.toSet().size)
        assertEquals(ids, ids.sortedDescending())
    }

    @Test
    fun eventLogKeysetPaginationStableUnderConcurrentInsert() = runBlocking {
        repeat(10) { eventLogDao.insert(createEventLog(message = "initial")) }

        val page1 = eventLogDao.getPageBefore(Long.MAX_VALUE, 5)
        assertEquals(5, page1.size)

        repeat(5) { eventLogDao.insert(createEventLog(message = "inserted later")) }

        val page2 = eventLogDao.getPageBefore(page1.last().id, 5)
        val combinedIds = (page1 + page2).map { it.id }
        assertEquals(combinedIds.size, combinedIds.toSet().size)
        assertTrue(page2.all { it.id < page1.last().id })
    }

    @Test
    fun eventLogTrimToMostRecent() = runBlocking {
        repeat(20) { i -> eventLogDao.insert(createEventLog(message = "event $i")) }

        eventLogDao.trimToMostRecent(5)

        assertEquals(5, eventLogDao.getCount())
        val remaining = eventLogDao.getRecent(100)
        assertEquals(5, remaining.size)
        assertEquals("event 19", remaining[0].message)
        assertEquals("event 15", remaining[4].message)
    }

    @Test
    fun eventLogTrimNoOpWhenUnderCap() = runBlocking {
        repeat(3) { eventLogDao.insert(createEventLog()) }

        eventLogDao.trimToMostRecent(10)

        assertEquals(3, eventLogDao.getCount())
    }

    @Test
    fun eventLogDeleteOlderThan() = runBlocking {
        val now = System.currentTimeMillis()
        eventLogDao.insert(createEventLog(timestamp = now - 100000, message = "old"))
        eventLogDao.insert(createEventLog(timestamp = now - 1000, message = "recent"))

        eventLogDao.deleteOlderThan(now - 50000)

        val remaining = eventLogDao.getRecent(100)
        assertEquals(1, remaining.size)
        assertEquals("recent", remaining[0].message)
    }

    @Test
    fun eventLogDeleteAll() = runBlocking {
        repeat(5) { eventLogDao.insert(createEventLog()) }

        eventLogDao.deleteAll()

        assertEquals(0, eventLogDao.getCount())
        assertTrue(eventLogDao.getRecent(10).isEmpty())
    }
}
