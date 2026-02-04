package io.privkey.keep.nip55

import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class RiskAssessorTest {

    @Test
    fun `score 0 for normal request with history`() = runTest {
        val auditDao = FakeAuditLogDao(kindCount = 5, recentCount = 2)
        val appSettingsDao = FakeAppSettingsDao(appAge = 7 * 24 * 60 * 60 * 1000L)

        val assessor = RiskAssessor(auditDao, appSettingsDao)
        val result = assessor.assess("com.example.app", 1)

        assertEquals(0, result.score)
        assertEquals(AuthLevel.NONE, result.requiredAuth)
        assertTrue(result.factors.isEmpty())
    }

    @Test
    fun `sensitive kind adds 40 points`() = runTest {
        val auditDao = FakeAuditLogDao(kindCount = 5, recentCount = 2)
        val appSettingsDao = FakeAppSettingsDao(appAge = 7 * 24 * 60 * 60 * 1000L)

        val assessor = RiskAssessor(auditDao, appSettingsDao)
        val result = assessor.assess("com.example.app", 10002)

        assertTrue(result.factors.contains(RiskFactor.SENSITIVE_EVENT_KIND))
        assertEquals(40, result.score)
        assertEquals(AuthLevel.BIOMETRIC, result.requiredAuth)
    }

    @Test
    fun `first kind adds 15 points`() = runTest {
        val auditDao = FakeAuditLogDao(kindCount = 0, recentCount = 2)
        val appSettingsDao = FakeAppSettingsDao(appAge = 7 * 24 * 60 * 60 * 1000L)

        val assessor = RiskAssessor(auditDao, appSettingsDao)
        val result = assessor.assess("com.example.app", 1)

        assertTrue(result.factors.contains(RiskFactor.FIRST_KIND))
        assertEquals(15, result.score)
    }

    @Test
    fun `high frequency adds 20 points`() = runTest {
        val auditDao = FakeAuditLogDao(kindCount = 5, recentCount = 15)
        val appSettingsDao = FakeAppSettingsDao(appAge = 7 * 24 * 60 * 60 * 1000L)

        val assessor = RiskAssessor(auditDao, appSettingsDao)
        val result = assessor.assess("com.example.app", 1)

        assertTrue(result.factors.contains(RiskFactor.HIGH_FREQUENCY))
        assertEquals(20, result.score)
        assertEquals(AuthLevel.PIN, result.requiredAuth)
    }

    @Test
    fun `new app adds 15 points`() = runTest {
        val auditDao = FakeAuditLogDao(kindCount = 5, recentCount = 2)
        val appSettingsDao = FakeAppSettingsDao(appAge = 12 * 60 * 60 * 1000L)

        val assessor = RiskAssessor(auditDao, appSettingsDao)
        val result = assessor.assess("com.example.app", 1)

        assertTrue(result.factors.contains(RiskFactor.NEW_APP))
        assertEquals(15, result.score)
    }

    @Test
    fun `combined factors escalate to EXPLICIT at 60`() = runTest {
        val auditDao = FakeAuditLogDao(kindCount = 0, recentCount = 15)
        val appSettingsDao = FakeAppSettingsDao(appAge = 12 * 60 * 60 * 1000L)

        val assessor = RiskAssessor(auditDao, appSettingsDao)
        val result = assessor.assess("com.example.app", 10002)

        assertTrue(result.score >= 60)
        assertEquals(AuthLevel.EXPLICIT, result.requiredAuth)
    }

    @Test
    fun `score capped at 100`() = runTest {
        val auditDao = FakeAuditLogDao(kindCount = 0, recentCount = 100)
        val appSettingsDao = FakeAppSettingsDao(appAge = 1000L)

        val assessor = RiskAssessor(auditDao, appSettingsDao)
        val result = assessor.assess("com.example.app", 0)

        assertEquals(100, result.score)
    }

    @Test
    fun `null eventKind skips kind-based factors`() = runTest {
        val auditDao = FakeAuditLogDao(kindCount = 0, recentCount = 2)
        val appSettingsDao = FakeAppSettingsDao(appAge = 7 * 24 * 60 * 60 * 1000L)

        val assessor = RiskAssessor(auditDao, appSettingsDao)
        val result = assessor.assess("com.example.app", null)

        assertFalse(result.factors.contains(RiskFactor.SENSITIVE_EVENT_KIND))
        assertFalse(result.factors.contains(RiskFactor.FIRST_KIND))
    }

    private class FakeAuditLogDao(
        private val kindCount: Int = 0,
        private val recentCount: Int = 0
    ) : Nip55AuditLogDao {
        override suspend fun insert(log: Nip55AuditLog): Long = 0
        override suspend fun getRecent(limit: Int): List<Nip55AuditLog> = emptyList()
        override suspend fun getForCaller(callerPackage: String, limit: Int): List<Nip55AuditLog> = emptyList()
        override suspend fun deleteOlderThan(before: Long) {}
        override suspend fun getLastUsedTime(callerPackage: String): Long? = null
        override suspend fun getPage(limit: Int, offset: Int): List<Nip55AuditLog> = emptyList()
        override suspend fun getPageForCaller(callerPackage: String, limit: Int, offset: Int): List<Nip55AuditLog> = emptyList()
        override suspend fun getDistinctCallers(): List<String> = emptyList()
        override suspend fun getLastUsedTimeForPermission(callerPackage: String, requestType: String, eventKind: Int): Long? = null
        override suspend fun getLastEntryHash(): String? = null
        override suspend fun getAllOrdered(): List<Nip55AuditLog> = emptyList()
        override suspend fun getCount(): Int = 0
        override suspend fun countByPackageAndKind(packageName: String, eventKind: Int): Int = kindCount
        override suspend fun countSince(packageName: String, since: Long): Int = recentCount
    }

    private class FakeAppSettingsDao(
        private val appAge: Long = 0
    ) : Nip55AppSettingsDao {
        override suspend fun getSettings(callerPackage: String): Nip55AppSettings? {
            val now = System.currentTimeMillis()
            return Nip55AppSettings(
                callerPackage = callerPackage,
                expiresAt = null,
                signPolicyOverride = null,
                createdAt = now - appAge,
                createdAtElapsed = 0,
                durationMs = null
            )
        }
        override suspend fun insertOrUpdate(settings: Nip55AppSettings) {}
        override suspend fun delete(callerPackage: String) {}
        override suspend fun getExpiredPackages(now: Long, nowElapsed: Long): List<String> = emptyList()
        override suspend fun deleteExpired(now: Long, nowElapsed: Long) {}
        override suspend fun getAll(): List<Nip55AppSettings> = emptyList()
    }
}
