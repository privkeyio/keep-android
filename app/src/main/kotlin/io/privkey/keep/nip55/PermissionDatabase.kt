package io.privkey.keep.nip55

import android.content.Context
import android.util.Log
import androidx.annotation.StringRes
import androidx.room.*
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import io.privkey.keep.R
import io.privkey.keep.uniffi.Nip55RequestType

@Entity(
    tableName = "nip55_permissions",
    indices = [Index(value = ["callerPackage", "requestType", "eventKind"], unique = true)]
)
data class Nip55Permission(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val callerPackage: String,
    val requestType: String,
    val eventKind: Int?,
    val decision: String,
    val expiresAt: Long?,
    val createdAt: Long
) {
    fun isExpired(): Boolean = expiresAt != null && expiresAt < System.currentTimeMillis()
}

@Entity(tableName = "nip55_audit_log")
data class Nip55AuditLog(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long,
    val callerPackage: String,
    val requestType: String,
    val eventKind: Int?,
    val decision: String,
    val wasAutomatic: Boolean
)

@Dao
interface Nip55PermissionDao {
    @Query("""
        SELECT * FROM nip55_permissions
        WHERE callerPackage = :callerPackage
        AND requestType = :requestType
        AND (eventKind IS NULL OR eventKind = :eventKind)
        ORDER BY eventKind DESC
        LIMIT 1
    """)
    suspend fun getPermission(callerPackage: String, requestType: String, eventKind: Int?): Nip55Permission?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPermission(permission: Nip55Permission)

    @Query("DELETE FROM nip55_permissions WHERE expiresAt IS NOT NULL AND expiresAt < :now")
    suspend fun deleteExpired(now: Long = System.currentTimeMillis())

    @Query("DELETE FROM nip55_permissions WHERE callerPackage = :callerPackage")
    suspend fun deleteForCaller(callerPackage: String)

    @Query("DELETE FROM nip55_permissions WHERE callerPackage = :callerPackage AND requestType = :requestType")
    suspend fun deleteForCallerAndType(callerPackage: String, requestType: String)

    @Query("SELECT * FROM nip55_permissions ORDER BY createdAt DESC")
    suspend fun getAll(): List<Nip55Permission>

    @Query("SELECT DISTINCT callerPackage FROM nip55_permissions WHERE expiresAt IS NULL OR expiresAt > :now")
    suspend fun getAllCallerPackages(now: Long): List<String>

    @Query("SELECT * FROM nip55_permissions WHERE callerPackage = :callerPackage AND (expiresAt IS NULL OR expiresAt > :now) ORDER BY createdAt DESC")
    suspend fun getForCaller(callerPackage: String, now: Long): List<Nip55Permission>

    @Query("SELECT COUNT(*) FROM nip55_permissions WHERE callerPackage = :callerPackage AND (expiresAt IS NULL OR expiresAt > :now)")
    suspend fun getPermissionCountForCaller(callerPackage: String, now: Long): Int

    @Query("DELETE FROM nip55_permissions WHERE callerPackage = :callerPackage AND requestType = :requestType AND eventKind = :eventKind")
    suspend fun deleteForCallerAndTypeAndEventKind(callerPackage: String, requestType: String, eventKind: Int)

    @Query("DELETE FROM nip55_permissions WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("SELECT DISTINCT callerPackage FROM nip55_permissions ORDER BY callerPackage")
    suspend fun getDistinctCallers(): List<String>
}

@Dao
interface Nip55AuditLogDao {
    @Insert
    suspend fun insert(log: Nip55AuditLog)

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
}

@Database(entities = [Nip55Permission::class, Nip55AuditLog::class], version = 1)
abstract class Nip55Database : RoomDatabase() {
    abstract fun permissionDao(): Nip55PermissionDao
    abstract fun auditLogDao(): Nip55AuditLogDao

    companion object {
        @Volatile
        private var INSTANCE: Nip55Database? = null

        // When bumping the database version, add a corresponding MIGRATION_X_Y object here.
        // Example for version 2:
        //   val MIGRATION_1_2 = object : Migration(1, 2) {
        //       override fun migrate(db: SupportSQLiteDatabase) {
        //           db.execSQL("ALTER TABLE nip55_permissions ADD COLUMN newColumn TEXT")
        //       }
        //   }
        // Then add it to addMigrations() below.
        private val MIGRATIONS = arrayOf<Migration>()

        fun getInstance(context: Context): Nip55Database {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    Nip55Database::class.java,
                    "nip55_permissions.db"
                ).addMigrations(*MIGRATIONS).build().also { INSTANCE = it }
            }
        }
    }
}

enum class PermissionDuration(val millis: Long?, @StringRes val displayNameRes: Int) {
    JUST_THIS_TIME(null, R.string.permission_duration_just_this_time),
    ONE_HOUR(60 * 60 * 1000L, R.string.permission_duration_one_hour),
    ONE_DAY(24 * 60 * 60 * 1000L, R.string.permission_duration_one_day),
    FOREVER(null, R.string.permission_duration_forever);

    fun expiresAt(): Long? = millis?.let { System.currentTimeMillis() + it }

    val shouldPersist: Boolean
        get() = this != JUST_THIS_TIME
}

data class ConnectedAppInfo(
    val packageName: String,
    val permissionCount: Int,
    val lastUsedTime: Long?
)

class PermissionStore(db: Nip55Database) {
    private val dao = db.permissionDao()
    private val auditDao = db.auditLogDao()

    companion object {
        private const val TAG = "PermissionStore"
    }

    suspend fun cleanupExpired() {
        dao.deleteExpired()
        auditDao.deleteOlderThan(System.currentTimeMillis() - 30L * 24 * 60 * 60 * 1000)
    }

    suspend fun hasPermission(callerPackage: String, requestType: Nip55RequestType, eventKind: Int? = null): Boolean? {
        val permission = dao.getPermission(callerPackage, requestType.name, eventKind)
        if (permission != null && !permission.isExpired()) return permission.decision == "allow"

        if (eventKind != null) {
            val genericPermission = dao.getPermission(callerPackage, requestType.name, null)
            if (genericPermission != null && !genericPermission.isExpired()) return genericPermission.decision == "allow"
        }
        return null
    }

    suspend fun grantPermission(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        duration: PermissionDuration
    ) = savePermission(callerPackage, requestType, eventKind, duration, "allow")

    suspend fun denyPermission(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        duration: PermissionDuration
    ) = savePermission(callerPackage, requestType, eventKind, duration, "deny")

    private suspend fun savePermission(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        duration: PermissionDuration,
        decision: String
    ) {
        if (!duration.shouldPersist) return
        dao.insertPermission(
            Nip55Permission(
                callerPackage = callerPackage,
                requestType = requestType.name,
                eventKind = eventKind,
                decision = decision,
                expiresAt = duration.expiresAt(),
                createdAt = System.currentTimeMillis()
            )
        )
    }

    suspend fun revokePermission(callerPackage: String, requestType: Nip55RequestType? = null, eventKind: Int? = null) =
        when {
            requestType == null -> dao.deleteForCaller(callerPackage)
            eventKind != null -> dao.deleteForCallerAndTypeAndEventKind(callerPackage, requestType.name, eventKind)
            else -> dao.deleteForCallerAndType(callerPackage, requestType.name)
        }

    suspend fun logOperation(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        decision: String,
        wasAutomatic: Boolean
    ) {
        auditDao.insert(
            Nip55AuditLog(
                timestamp = System.currentTimeMillis(),
                callerPackage = callerPackage,
                requestType = requestType.name,
                eventKind = eventKind,
                decision = decision,
                wasAutomatic = wasAutomatic
            )
        )
    }

    suspend fun getAllPermissions(): List<Nip55Permission> = dao.getAll()

    suspend fun getAuditLog(limit: Int = 100): List<Nip55AuditLog> = auditDao.getRecent(limit)

    suspend fun getConnectedApps(): List<ConnectedAppInfo> {
        val now = System.currentTimeMillis()
        val packages = dao.getAllCallerPackages(now)
        return packages.map { pkg ->
            ConnectedAppInfo(
                packageName = pkg,
                permissionCount = dao.getPermissionCountForCaller(pkg, now),
                lastUsedTime = auditDao.getLastUsedTime(pkg)
            )
        }.sortedByDescending { it.lastUsedTime ?: 0L }
    }

    suspend fun getPermissionsForCaller(callerPackage: String): List<Nip55Permission> =
        dao.getForCaller(callerPackage, System.currentTimeMillis())

    suspend fun deletePermission(id: Long) {
        Log.d(TAG, "Deleting permission id=$id")
        dao.deleteById(id)
    }

    suspend fun revokeAllForApp(callerPackage: String) {
        Log.d(TAG, "Revoking all permissions for $callerPackage")
        dao.deleteForCaller(callerPackage)
    }

    suspend fun getDistinctPermissionCallers(): List<String> = dao.getDistinctCallers()

    suspend fun getAuditLogPage(
        limit: Int,
        offset: Int,
        callerPackage: String? = null
    ): List<Nip55AuditLog> {
        val safeLimit = limit.coerceIn(1, 100)
        val safeOffset = offset.coerceAtLeast(0)
        return if (callerPackage != null) {
            auditDao.getPageForCaller(callerPackage, safeLimit, safeOffset)
        } else {
            auditDao.getPage(safeLimit, safeOffset)
        }
    }

    suspend fun getDistinctAuditCallers(): List<String> = auditDao.getDistinctCallers()
}

fun formatRequestType(type: String): String =
    type.replace("_", " ").lowercase().replaceFirstChar { it.uppercase() }
