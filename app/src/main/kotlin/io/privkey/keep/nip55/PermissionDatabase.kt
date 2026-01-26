package io.privkey.keep.nip55

import android.content.Context
import androidx.room.*
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
)

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
}

@Database(entities = [Nip55Permission::class, Nip55AuditLog::class], version = 1)
abstract class Nip55Database : RoomDatabase() {
    abstract fun permissionDao(): Nip55PermissionDao
    abstract fun auditLogDao(): Nip55AuditLogDao

    companion object {
        @Volatile
        private var INSTANCE: Nip55Database? = null

        fun getInstance(context: Context): Nip55Database {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    Nip55Database::class.java,
                    "nip55_permissions.db"
                ).build().also { INSTANCE = it }
            }
        }
    }
}

enum class PermissionDuration(val millis: Long?, val displayName: String) {
    JUST_THIS_TIME(null, "Just this time"),
    ONE_HOUR(60 * 60 * 1000L, "For 1 hour"),
    ONE_DAY(24 * 60 * 60 * 1000L, "For 24 hours"),
    FOREVER(null, "Always");

    fun expiresAt(): Long? = millis?.let { System.currentTimeMillis() + it }

    val shouldPersist: Boolean
        get() = this != JUST_THIS_TIME
}

class PermissionStore(db: Nip55Database) {
    private val dao = db.permissionDao()
    private val auditDao = db.auditLogDao()

    suspend fun cleanupExpired() {
        dao.deleteExpired()
    }

    suspend fun hasPermission(callerPackage: String, requestType: Nip55RequestType, eventKind: Int? = null): Boolean? {
        val permission = dao.getPermission(callerPackage, requestType.name, eventKind) ?: return null
        val expired = permission.expiresAt != null && permission.expiresAt < System.currentTimeMillis()
        if (expired) return null
        return permission.decision == "allow"
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

    suspend fun revokePermission(callerPackage: String, requestType: Nip55RequestType? = null) {
        if (requestType == null) {
            dao.deleteForCaller(callerPackage)
        } else {
            dao.deleteForCallerAndType(callerPackage, requestType.name)
        }
    }

    suspend fun logOperation(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        decision: String,
        wasAutomatic: Boolean
    ) {
        val log = Nip55AuditLog(
            timestamp = System.currentTimeMillis(),
            callerPackage = callerPackage,
            requestType = requestType.name,
            eventKind = eventKind,
            decision = decision,
            wasAutomatic = wasAutomatic
        )
        auditDao.insert(log)
    }

    suspend fun getAllPermissions(): List<Nip55Permission> = dao.getAll()

    suspend fun getAuditLog(limit: Int = 100): List<Nip55AuditLog> = auditDao.getRecent(limit)
}
