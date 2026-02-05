package io.privkey.keep.nip55

import androidx.room.*

@Dao
interface Nip55PermissionDao {
    @Query("""
        SELECT * FROM nip55_permissions
        WHERE callerPackage = :callerPackage
        AND requestType = :requestType
        AND eventKind = :eventKind
        ORDER BY eventKind DESC
        LIMIT 1
    """)
    suspend fun getPermission(callerPackage: String, requestType: String, eventKind: Int): Nip55Permission?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPermission(permission: Nip55Permission)

    @Query("""
        DELETE FROM nip55_permissions WHERE
        (expiresAt IS NOT NULL AND expiresAt <= :now)
        OR (expiresAt IS NOT NULL AND :now < createdAt)
        OR (createdAtElapsed > 0 AND durationMs IS NOT NULL AND (createdAtElapsed + durationMs) <= :nowElapsed)
        OR (createdAtElapsed > 0 AND durationMs IS NOT NULL AND createdAtElapsed > :nowElapsed)
    """)
    suspend fun deleteExpired(now: Long = System.currentTimeMillis(), nowElapsed: Long = android.os.SystemClock.elapsedRealtime())

    @Query("DELETE FROM nip55_permissions WHERE callerPackage = :callerPackage")
    suspend fun deleteForCaller(callerPackage: String)

    @Query("DELETE FROM nip55_permissions WHERE callerPackage = :callerPackage AND requestType = :requestType")
    suspend fun deleteForCallerAndType(callerPackage: String, requestType: String)

    @Query("SELECT * FROM nip55_permissions ORDER BY createdAt DESC")
    suspend fun getAll(): List<Nip55Permission>

    @Query("""
        SELECT DISTINCT callerPackage FROM nip55_permissions WHERE
        (expiresAt IS NULL OR expiresAt > :now)
        AND (expiresAt IS NULL OR :now >= createdAt)
        AND (createdAtElapsed <= 0 OR durationMs IS NULL OR (createdAtElapsed + durationMs) > :nowElapsed)
        AND (createdAtElapsed <= 0 OR durationMs IS NULL OR createdAtElapsed <= :nowElapsed)
    """)
    suspend fun getAllCallerPackages(now: Long, nowElapsed: Long = android.os.SystemClock.elapsedRealtime()): List<String>

    @Query("""
        SELECT * FROM nip55_permissions WHERE callerPackage = :callerPackage
        AND (expiresAt IS NULL OR expiresAt > :now)
        AND (expiresAt IS NULL OR :now >= createdAt)
        AND (createdAtElapsed <= 0 OR durationMs IS NULL OR (createdAtElapsed + durationMs) > :nowElapsed)
        AND (createdAtElapsed <= 0 OR durationMs IS NULL OR createdAtElapsed <= :nowElapsed)
        ORDER BY createdAt DESC
    """)
    suspend fun getForCaller(callerPackage: String, now: Long, nowElapsed: Long = android.os.SystemClock.elapsedRealtime()): List<Nip55Permission>

    @Query("""
        SELECT COUNT(*) FROM nip55_permissions WHERE callerPackage = :callerPackage
        AND (expiresAt IS NULL OR expiresAt > :now)
        AND (expiresAt IS NULL OR :now >= createdAt)
        AND (createdAtElapsed <= 0 OR durationMs IS NULL OR (createdAtElapsed + durationMs) > :nowElapsed)
        AND (createdAtElapsed <= 0 OR durationMs IS NULL OR createdAtElapsed <= :nowElapsed)
    """)
    suspend fun getPermissionCountForCaller(callerPackage: String, now: Long, nowElapsed: Long = android.os.SystemClock.elapsedRealtime()): Int

    @Query("DELETE FROM nip55_permissions WHERE callerPackage = :callerPackage AND requestType = :requestType AND eventKind = :eventKind")
    suspend fun deleteForCallerAndTypeAndEventKind(callerPackage: String, requestType: String, eventKind: Int)

    @Query("DELETE FROM nip55_permissions WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("SELECT DISTINCT callerPackage FROM nip55_permissions ORDER BY callerPackage")
    suspend fun getDistinctCallers(): List<String>

    @Query("UPDATE nip55_permissions SET decision = :decision WHERE id = :id")
    suspend fun updateDecision(id: Long, decision: String)

    @Query("SELECT * FROM nip55_permissions WHERE id = :id")
    suspend fun getById(id: Long): Nip55Permission?
}

@Dao
interface Nip55AuditLogDao {
    @Insert
    suspend fun insert(log: Nip55AuditLog): Long

    @Query("SELECT * FROM nip55_audit_log ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getRecent(limit: Int = 100): List<Nip55AuditLog>

    @Query("SELECT * FROM nip55_audit_log WHERE callerPackage = :callerPackage ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getForCaller(callerPackage: String, limit: Int = 100): List<Nip55AuditLog>

    @Query("DELETE FROM nip55_audit_log WHERE timestamp < :before")
    suspend fun deleteOlderThan(before: Long)

    @Query("SELECT MAX(timestamp) FROM nip55_audit_log WHERE callerPackage = :callerPackage AND decision = 'allow'")
    suspend fun getLastUsedTime(callerPackage: String): Long?

    @Query("SELECT * FROM nip55_audit_log ORDER BY timestamp DESC LIMIT :limit OFFSET :offset")
    suspend fun getPage(limit: Int, offset: Int): List<Nip55AuditLog>

    @Query("SELECT * FROM nip55_audit_log WHERE callerPackage = :callerPackage ORDER BY timestamp DESC LIMIT :limit OFFSET :offset")
    suspend fun getPageForCaller(callerPackage: String, limit: Int, offset: Int): List<Nip55AuditLog>

    @Query("SELECT DISTINCT callerPackage FROM nip55_audit_log ORDER BY callerPackage")
    suspend fun getDistinctCallers(): List<String>

    @Query("""
        SELECT MAX(timestamp) FROM nip55_audit_log
        WHERE callerPackage = :callerPackage
        AND requestType = :requestType
        AND eventKind = :eventKind
        AND decision = 'allow'
    """)
    suspend fun getLastUsedTimeForPermission(callerPackage: String, requestType: String, eventKind: Int): Long?

    @Query("SELECT COUNT(*) FROM nip55_audit_log WHERE callerPackage = :packageName AND eventKind = :eventKind AND decision = 'allow'")
    suspend fun countByPackageAndKind(packageName: String, eventKind: Int): Int

    @Query("SELECT COUNT(*) FROM nip55_audit_log WHERE callerPackage = :packageName AND timestamp >= :since")
    suspend fun countSince(packageName: String, since: Long): Int

    @Query("SELECT entryHash FROM nip55_audit_log ORDER BY id DESC LIMIT 1")
    suspend fun getLastEntryHash(): String?

    @Query("SELECT * FROM nip55_audit_log ORDER BY id ASC")
    suspend fun getAllOrdered(): List<Nip55AuditLog>

    @Query("SELECT COUNT(*) FROM nip55_audit_log")
    suspend fun getCount(): Int
}

@Dao
interface VelocityDao {
    @Insert
    suspend fun insert(entry: VelocityEntry)

    @Query("SELECT COUNT(*) FROM velocity_tracker WHERE packageName = :packageName AND timestamp >= :since")
    suspend fun countSince(packageName: String, since: Long): Int

    @Query("DELETE FROM velocity_tracker WHERE timestamp < :before")
    suspend fun deleteOlderThan(before: Long)

    @Query("SELECT MIN(timestamp) FROM velocity_tracker WHERE packageName = :packageName AND timestamp >= :since")
    suspend fun getOldestInWindow(packageName: String, since: Long): Long?
}

@Dao
interface Nip55AppSettingsDao {
    @Query("SELECT * FROM nip55_app_settings WHERE callerPackage = :callerPackage")
    suspend fun getSettings(callerPackage: String): Nip55AppSettings?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdate(settings: Nip55AppSettings)

    @Query("DELETE FROM nip55_app_settings WHERE callerPackage = :callerPackage")
    suspend fun delete(callerPackage: String)

    @Query("""
        SELECT callerPackage FROM nip55_app_settings WHERE
        (expiresAt IS NOT NULL AND expiresAt <= :now)
        OR (expiresAt IS NOT NULL AND :now < createdAt)
        OR (createdAtElapsed > 0 AND durationMs IS NOT NULL AND (createdAtElapsed + durationMs) <= :nowElapsed)
        OR (createdAtElapsed > 0 AND durationMs IS NOT NULL AND createdAtElapsed > :nowElapsed)
    """)
    suspend fun getExpiredPackages(now: Long = System.currentTimeMillis(), nowElapsed: Long = android.os.SystemClock.elapsedRealtime()): List<String>

    @Query("""
        DELETE FROM nip55_app_settings WHERE
        (expiresAt IS NOT NULL AND expiresAt <= :now)
        OR (expiresAt IS NOT NULL AND :now < createdAt)
        OR (createdAtElapsed > 0 AND durationMs IS NOT NULL AND (createdAtElapsed + durationMs) <= :nowElapsed)
        OR (createdAtElapsed > 0 AND durationMs IS NOT NULL AND createdAtElapsed > :nowElapsed)
    """)
    suspend fun deleteExpired(now: Long = System.currentTimeMillis(), nowElapsed: Long = android.os.SystemClock.elapsedRealtime())

    @Query("SELECT * FROM nip55_app_settings")
    suspend fun getAll(): List<Nip55AppSettings>
}
