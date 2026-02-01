package io.privkey.keep.nip55

import android.content.Context
import androidx.annotation.StringRes
import androidx.room.*
import androidx.room.migration.Migration
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.privkey.keep.R
import io.privkey.keep.uniffi.Nip55RequestType
import net.sqlcipher.database.SupportFactory
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

enum class PermissionDecision(@StringRes val displayNameRes: Int) {
    ALLOW(R.string.permission_decision_allow),
    DENY(R.string.permission_decision_deny),
    ASK(R.string.permission_decision_ask);

    companion object {
        fun fromString(value: String): PermissionDecision = when (value.lowercase()) {
            "allow" -> ALLOW
            "deny" -> DENY
            "ask" -> ASK
            else -> DENY
        }
    }

    override fun toString(): String = name.lowercase()
}

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
    fun isExpired(): Boolean = isTimestampExpired(expiresAt, createdAt)

    val permissionDecision: PermissionDecision
        get() = PermissionDecision.fromString(decision)
}

@Entity(tableName = "nip55_audit_log")
data class Nip55AuditLog(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long,
    val callerPackage: String,
    val requestType: String,
    val eventKind: Int?,
    val decision: String,
    val wasAutomatic: Boolean,
    val previousHash: String? = null,
    val entryHash: String = ""
)

@Entity(
    tableName = "velocity_tracker",
    indices = [Index(value = ["packageName", "timestamp"])]
)
data class VelocityEntry(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val packageName: String,
    val timestamp: Long,
    val eventKind: Int?
)

data class VelocityConfig(
    val hourlyLimit: Int = 100,
    val dailyLimit: Int = 500,
    val weeklyLimit: Int = 2000,
    val enabled: Boolean = true
)

sealed class VelocityResult {
    data object Allowed : VelocityResult()
    data class Blocked(val reason: String, val resetAt: Long) : VelocityResult()
}

sealed class ChainVerificationResult {
    data object Valid : ChainVerificationResult()
    data class PartiallyVerified(val legacyEntriesSkipped: Int) : ChainVerificationResult()
    data class Broken(val entryId: Long) : ChainVerificationResult()
    data class Tampered(val entryId: Long) : ChainVerificationResult()
}

@Entity(tableName = "nip55_app_settings")
data class Nip55AppSettings(
    @PrimaryKey val callerPackage: String,
    val expiresAt: Long?,
    val signPolicyOverride: Int?,
    val createdAt: Long
) {
    fun isExpired(): Boolean = isTimestampExpired(expiresAt, createdAt)
}

@Dao
interface Nip55PermissionDao {
    @Query("""
        SELECT * FROM nip55_permissions
        WHERE callerPackage = :callerPackage
        AND requestType = :requestType
        AND ((:eventKind IS NULL AND eventKind IS NULL) OR (:eventKind IS NOT NULL AND eventKind = :eventKind))
        ORDER BY eventKind DESC
        LIMIT 1
    """)
    suspend fun getPermission(callerPackage: String, requestType: String, eventKind: Int?): Nip55Permission?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPermission(permission: Nip55Permission)

    @Query("DELETE FROM nip55_permissions WHERE expiresAt IS NOT NULL AND expiresAt <= :now")
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
        AND ((:eventKind IS NULL AND eventKind IS NULL) OR (:eventKind IS NOT NULL AND eventKind = :eventKind))
        AND decision = 'allow'
    """)
    suspend fun getLastUsedTimeForPermission(callerPackage: String, requestType: String, eventKind: Int?): Long?

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

    @Query("SELECT callerPackage FROM nip55_app_settings WHERE expiresAt IS NOT NULL AND expiresAt <= :now")
    suspend fun getExpiredPackages(now: Long = System.currentTimeMillis()): List<String>

    @Query("DELETE FROM nip55_app_settings WHERE expiresAt IS NOT NULL AND expiresAt <= :now")
    suspend fun deleteExpired(now: Long = System.currentTimeMillis())

    @Query("SELECT * FROM nip55_app_settings")
    suspend fun getAll(): List<Nip55AppSettings>
}

@Database(entities = [Nip55Permission::class, Nip55AuditLog::class, Nip55AppSettings::class, VelocityEntry::class], version = 4)
abstract class Nip55Database : RoomDatabase() {
    abstract fun permissionDao(): Nip55PermissionDao
    abstract fun auditLogDao(): Nip55AuditLogDao
    abstract fun appSettingsDao(): Nip55AppSettingsDao
    abstract fun velocityDao(): VelocityDao

    companion object {
        @Volatile
        private var INSTANCE: Nip55Database? = null

        private const val PREFS_NAME = "nip55_db_prefs"
        private const val KEY_DB_PASSPHRASE = "db_passphrase"
        private const val KEY_HMAC_SECRET = "hmac_secret"

        @Volatile
        private var hmacKey: ByteArray? = null

        private val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS nip55_app_settings (
                        callerPackage TEXT PRIMARY KEY NOT NULL,
                        expiresAt INTEGER,
                        createdAt INTEGER NOT NULL
                    )
                """)
            }
        }

        private val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE nip55_app_settings ADD COLUMN signPolicyOverride INTEGER")
            }
        }

        private val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE nip55_audit_log ADD COLUMN previousHash TEXT")
                db.execSQL("ALTER TABLE nip55_audit_log ADD COLUMN entryHash TEXT NOT NULL DEFAULT ''")
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS velocity_tracker (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        packageName TEXT NOT NULL,
                        timestamp INTEGER NOT NULL,
                        eventKind INTEGER
                    )
                """)
                db.execSQL("CREATE INDEX IF NOT EXISTS index_velocity_tracker_packageName_timestamp ON velocity_tracker(packageName, timestamp)")
            }
        }

        private val MIGRATIONS = arrayOf(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)

        private fun getOrCreateDbKey(context: Context): ByteArray {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            val prefs = EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            val existingKey = prefs.getString(KEY_DB_PASSPHRASE, null)
            if (existingKey != null) {
                return android.util.Base64.decode(existingKey, android.util.Base64.NO_WRAP)
            }

            val newKey = ByteArray(32)
            SecureRandom().nextBytes(newKey)
            prefs.edit()
                .putString(KEY_DB_PASSPHRASE, android.util.Base64.encodeToString(newKey, android.util.Base64.NO_WRAP))
                .apply()
            return newKey
        }

        private fun getOrCreateHmacKey(context: Context): ByteArray {
            hmacKey?.let { return it }

            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            val prefs = EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            val existingKey = prefs.getString(KEY_HMAC_SECRET, null)
            if (existingKey != null) {
                return android.util.Base64.decode(existingKey, android.util.Base64.NO_WRAP).also { hmacKey = it }
            }

            val newKey = ByteArray(32)
            SecureRandom().nextBytes(newKey)
            prefs.edit()
                .putString(KEY_HMAC_SECRET, android.util.Base64.encodeToString(newKey, android.util.Base64.NO_WRAP))
                .commit()
            return newKey.also { hmacKey = it }
        }

        fun getHmacKey(): ByteArray? = hmacKey

        fun getInstance(context: Context): Nip55Database {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: run {
                    val passphrase = getOrCreateDbKey(context.applicationContext)
                    getOrCreateHmacKey(context.applicationContext)
                    val factory = SupportFactory(passphrase)
                    Room.databaseBuilder(
                        context.applicationContext,
                        Nip55Database::class.java,
                        "nip55_permissions.db"
                    )
                        .openHelperFactory(factory)
                        .addMigrations(*MIGRATIONS)
                        .build()
                        .also { INSTANCE = it }
                }
            }
        }
    }
}

enum class PermissionDuration(val millis: Long?, @StringRes val displayNameRes: Int) {
    JUST_THIS_TIME(null, R.string.permission_duration_just_this_time),
    ONE_MINUTE(60 * 1000L, R.string.permission_duration_one_minute),
    FIVE_MINUTES(5 * 60 * 1000L, R.string.permission_duration_five_minutes),
    TEN_MINUTES(10 * 60 * 1000L, R.string.permission_duration_ten_minutes),
    ONE_HOUR(60 * 60 * 1000L, R.string.permission_duration_one_hour),
    ONE_DAY(24 * 60 * 60 * 1000L, R.string.permission_duration_one_day),
    FOREVER(null, R.string.permission_duration_forever);

    fun expiresAt(): Long? = millis?.let { System.currentTimeMillis() + it }

    val shouldPersist: Boolean
        get() = this != JUST_THIS_TIME
}

enum class AppExpiryDuration(val millis: Long?, @StringRes val displayNameRes: Int) {
    FIVE_MINUTES(5 * 60 * 1000L, R.string.app_expiry_five_minutes),
    ONE_HOUR(60 * 60 * 1000L, R.string.app_expiry_one_hour),
    ONE_DAY(24 * 60 * 60 * 1000L, R.string.app_expiry_one_day),
    ONE_WEEK(7 * 24 * 60 * 60 * 1000L, R.string.app_expiry_one_week),
    NEVER(null, R.string.app_expiry_never);

    fun expiresAt(): Long? = millis?.let { System.currentTimeMillis() + it }
}

data class ConnectedAppInfo(
    val packageName: String,
    val permissionCount: Int,
    val lastUsedTime: Long?,
    val expiresAt: Long?
)

class PermissionStore(private val database: Nip55Database) {
    private val dao = database.permissionDao()
    private val auditDao = database.auditLogDao()
    private val appSettingsDao = database.appSettingsDao()
    private val velocityDao = database.velocityDao()

    companion object {
        private const val HOUR_MS = 60 * 60 * 1000L
        private const val DAY_MS = 24 * HOUR_MS
        private const val WEEK_MS = 7 * DAY_MS
    }

    suspend fun cleanupExpired() {
        val now = System.currentTimeMillis()
        dao.deleteExpired(now)
        auditDao.deleteOlderThan(now - 30L * 24 * 60 * 60 * 1000)
        val expiredPackages = appSettingsDao.getExpiredPackages(now)
        expiredPackages.forEach { pkg ->
            dao.deleteForCaller(pkg)
        }
        appSettingsDao.deleteExpired(now)
    }

    suspend fun getPermissionDecision(callerPackage: String, requestType: Nip55RequestType, eventKind: Int? = null): PermissionDecision? {
        val permission = dao.getPermission(callerPackage, requestType.name, eventKind)
        if (permission != null && !permission.isExpired()) return permission.permissionDecision

        if (eventKind != null && !isSensitiveKind(eventKind)) {
            val genericPermission = dao.getPermission(callerPackage, requestType.name, null)
            if (genericPermission != null && !genericPermission.isExpired()) return genericPermission.permissionDecision
        }
        return null
    }

    suspend fun grantPermission(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        duration: PermissionDuration
    ) {
        val effectiveDuration = if (eventKind != null && isSensitiveKind(eventKind) && duration == PermissionDuration.FOREVER) {
            PermissionDuration.ONE_DAY
        } else {
            duration
        }
        savePermission(callerPackage, requestType, eventKind, effectiveDuration, "allow")
    }

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

    suspend fun revokePermission(callerPackage: String, requestType: Nip55RequestType? = null, eventKind: Int? = null) {
        when {
            requestType == null -> dao.deleteForCaller(callerPackage)
            eventKind != null -> dao.deleteForCallerAndTypeAndEventKind(callerPackage, requestType.name, eventKind)
            else -> dao.deleteForCallerAndType(callerPackage, requestType.name)
        }
    }

    suspend fun logOperation(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        decision: String,
        wasAutomatic: Boolean
    ) {
        database.withTransaction {
            val previousHash = auditDao.getLastEntryHash()
            val timestamp = System.currentTimeMillis()
            val entryHash = calculateEntryHash(
                previousHash = previousHash,
                callerPackage = callerPackage,
                requestType = requestType.name,
                eventKind = eventKind,
                decision = decision,
                timestamp = timestamp,
                wasAutomatic = wasAutomatic
            )
            auditDao.insert(
                Nip55AuditLog(
                    timestamp = timestamp,
                    callerPackage = callerPackage,
                    requestType = requestType.name,
                    eventKind = eventKind,
                    decision = decision,
                    wasAutomatic = wasAutomatic,
                    previousHash = previousHash,
                    entryHash = entryHash
                )
            )
        }
    }

    suspend fun checkAndRecordVelocity(packageName: String, eventKind: Int?, config: VelocityConfig = VelocityConfig()): VelocityResult {
        if (!config.enabled) return VelocityResult.Allowed

        return database.withTransaction {
            val now = System.currentTimeMillis()

            val hourCount = velocityDao.countSince(packageName, now - HOUR_MS)
            if (hourCount >= config.hourlyLimit) {
                val oldest = velocityDao.getOldestInWindow(packageName, now - HOUR_MS)
                val resetAt = (oldest ?: now) + HOUR_MS
                return@withTransaction VelocityResult.Blocked("Hourly limit ($hourCount/${config.hourlyLimit})", resetAt)
            }

            val dayCount = velocityDao.countSince(packageName, now - DAY_MS)
            if (dayCount >= config.dailyLimit) {
                val oldest = velocityDao.getOldestInWindow(packageName, now - DAY_MS)
                val resetAt = (oldest ?: now) + DAY_MS
                return@withTransaction VelocityResult.Blocked("Daily limit ($dayCount/${config.dailyLimit})", resetAt)
            }

            val weekCount = velocityDao.countSince(packageName, now - WEEK_MS)
            if (weekCount >= config.weeklyLimit) {
                val oldest = velocityDao.getOldestInWindow(packageName, now - WEEK_MS)
                val resetAt = (oldest ?: now) + WEEK_MS
                return@withTransaction VelocityResult.Blocked("Weekly limit ($weekCount/${config.weeklyLimit})", resetAt)
            }

            velocityDao.insert(VelocityEntry(packageName = packageName, timestamp = now, eventKind = eventKind))
            velocityDao.deleteOlderThan(now - WEEK_MS)

            VelocityResult.Allowed
        }
    }

    suspend fun getVelocityUsage(packageName: String): Triple<Int, Int, Int> {
        val now = System.currentTimeMillis()
        val hour = velocityDao.countSince(packageName, now - HOUR_MS)
        val day = velocityDao.countSince(packageName, now - DAY_MS)
        val week = velocityDao.countSince(packageName, now - WEEK_MS)
        return Triple(hour, day, week)
    }

    suspend fun verifyAuditChain(): ChainVerificationResult {
        val entries = auditDao.getAllOrdered()
        var inLegacyPhase = true
        var legacyEntriesSkipped = 0
        var expectedPrevHash: String? = null

        for (entry in entries) {
            if (inLegacyPhase) {
                if (entry.entryHash.isEmpty()) {
                    legacyEntriesSkipped++
                    continue
                }
                inLegacyPhase = false
                if (!entry.previousHash.isNullOrEmpty()) {
                    return ChainVerificationResult.Broken(entry.id)
                }
            } else {
                if (entry.entryHash.isEmpty()) {
                    return ChainVerificationResult.Broken(entry.id)
                }
                if (!constantTimeEquals(entry.previousHash, expectedPrevHash)) {
                    return ChainVerificationResult.Broken(entry.id)
                }
            }

            val calculated = calculateEntryHash(
                previousHash = entry.previousHash,
                callerPackage = entry.callerPackage,
                requestType = entry.requestType,
                eventKind = entry.eventKind,
                decision = entry.decision,
                timestamp = entry.timestamp,
                wasAutomatic = entry.wasAutomatic
            )
            if (!constantTimeEquals(calculated, entry.entryHash)) {
                return ChainVerificationResult.Tampered(entry.id)
            }

            expectedPrevHash = entry.entryHash
        }

        return if (legacyEntriesSkipped > 0) {
            ChainVerificationResult.PartiallyVerified(legacyEntriesSkipped)
        } else {
            ChainVerificationResult.Valid
        }
    }

    suspend fun getAuditLogCount(): Int = auditDao.getCount()

    suspend fun getAllPermissions(): List<Nip55Permission> = dao.getAll()

    suspend fun getAuditLog(limit: Int = 100): List<Nip55AuditLog> = auditDao.getRecent(limit)

    suspend fun getConnectedApps(): List<ConnectedAppInfo> {
        val now = System.currentTimeMillis()
        val packages = dao.getAllCallerPackages(now)
        return packages.map { pkg ->
            val appSettings = appSettingsDao.getSettings(pkg)
            ConnectedAppInfo(
                packageName = pkg,
                permissionCount = dao.getPermissionCountForCaller(pkg, now),
                lastUsedTime = auditDao.getLastUsedTime(pkg),
                expiresAt = appSettings?.expiresAt
            )
        }.sortedByDescending { it.lastUsedTime ?: 0L }
    }

    suspend fun getAppSettings(callerPackage: String): Nip55AppSettings? =
        appSettingsDao.getSettings(callerPackage)

    suspend fun setAppExpiry(callerPackage: String, duration: AppExpiryDuration) {
        val expiresAt = duration.expiresAt()
        val existing = appSettingsDao.getSettings(callerPackage)
        if (expiresAt == null && existing?.signPolicyOverride == null) {
            appSettingsDao.delete(callerPackage)
        } else {
            appSettingsDao.insertOrUpdate(
                Nip55AppSettings(
                    callerPackage = callerPackage,
                    expiresAt = expiresAt,
                    signPolicyOverride = existing?.signPolicyOverride,
                    createdAt = System.currentTimeMillis()
                )
            )
        }
    }

    suspend fun isAppExpired(callerPackage: String): Boolean {
        val settings = appSettingsDao.getSettings(callerPackage) ?: return false
        return settings.isExpired()
    }

    suspend fun getPermissionsForCaller(callerPackage: String): List<Nip55Permission> =
        dao.getForCaller(callerPackage, System.currentTimeMillis())

    suspend fun deletePermission(id: Long) = dao.deleteById(id)

    suspend fun updatePermissionDecision(
        id: Long,
        decision: PermissionDecision,
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?
    ) {
        val permission = dao.getById(id) ?: throw IllegalArgumentException("Permission not found: $id")
        if (permission.callerPackage != callerPackage) {
            throw IllegalArgumentException("CallerPackage mismatch for permission $id")
        }
        if (permission.requestType != requestType.name) {
            throw IllegalArgumentException("RequestType mismatch for permission $id: expected ${permission.requestType}, got ${requestType.name}")
        }
        val storedRequestType = findRequestType(permission.requestType)
            ?: throw IllegalArgumentException("Unknown requestType in permission $id: ${permission.requestType}")
        database.withTransaction {
            dao.updateDecision(id, decision.toString())
            logOperation(permission.callerPackage, storedRequestType, permission.eventKind, decision.toString(), wasAutomatic = false)
        }
    }

    suspend fun setPermissionToAsk(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?
    ) {
        database.withTransaction {
            dao.insertPermission(
                Nip55Permission(
                    callerPackage = callerPackage,
                    requestType = requestType.name,
                    eventKind = eventKind,
                    decision = PermissionDecision.ASK.toString(),
                    expiresAt = null,
                    createdAt = System.currentTimeMillis()
                )
            )
            logOperation(callerPackage, requestType, eventKind, PermissionDecision.ASK.toString(), wasAutomatic = false)
        }
    }

    suspend fun revokeAllForApp(callerPackage: String) = dao.deleteForCaller(callerPackage)

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

    suspend fun getLastUsedTimeForPermission(
        callerPackage: String,
        requestType: String,
        eventKind: Int?
    ): Long? = auditDao.getLastUsedTimeForPermission(callerPackage, requestType, eventKind)

    suspend fun getAppSignPolicyOverride(callerPackage: String): Int? =
        appSettingsDao.getSettings(callerPackage)?.signPolicyOverride

    suspend fun setAppSignPolicyOverride(callerPackage: String, signPolicyOrdinal: Int?) {
        val existing = appSettingsDao.getSettings(callerPackage)
        if (signPolicyOrdinal == null && existing?.expiresAt == null) {
            appSettingsDao.delete(callerPackage)
        } else {
            appSettingsDao.insertOrUpdate(
                Nip55AppSettings(
                    callerPackage = callerPackage,
                    expiresAt = existing?.expiresAt,
                    signPolicyOverride = signPolicyOrdinal,
                    createdAt = existing?.createdAt ?: System.currentTimeMillis()
                )
            )
        }
    }

    suspend fun clearAppSettings(callerPackage: String) {
        appSettingsDao.delete(callerPackage)
    }
}

private fun isTimestampExpired(expiresAt: Long?, createdAt: Long): Boolean {
    if (expiresAt == null) return false
    val now = System.currentTimeMillis()
    val clockManipulated = now < createdAt
    return clockManipulated || expiresAt <= now
}

fun formatRequestType(type: String): String =
    type.replace("_", " ").lowercase().replaceFirstChar { it.uppercase() }

fun formatRelativeTime(timestamp: Long): String {
    val diff = System.currentTimeMillis() - timestamp
    return when {
        diff < 60_000 -> "just now"
        diff < 3600_000 -> "${diff / 60_000}m ago"
        diff < 86400_000 -> "${diff / 3600_000}h ago"
        diff < 604800_000 -> "${diff / 86400_000}d ago"
        else -> java.text.SimpleDateFormat("MMM d", java.util.Locale.getDefault()).format(java.util.Date(timestamp))
    }
}

fun findRequestType(name: String): Nip55RequestType? =
    Nip55RequestType.entries.find { it.name == name }

fun formatExpiry(timestamp: Long): String {
    val remaining = timestamp - System.currentTimeMillis()
    return when {
        remaining <= 0 -> "expired"
        remaining < 60_000 -> "<1m"
        remaining < 3600_000 -> "in ${remaining / 60_000}m"
        remaining < 86400_000 -> "in ${remaining / 3600_000}h"
        remaining < 604800_000 -> "in ${remaining / 86400_000}d"
        else -> java.text.SimpleDateFormat("MMM d", java.util.Locale.getDefault()).format(java.util.Date(timestamp))
    }
}

private fun calculateEntryHash(
    previousHash: String?,
    callerPackage: String,
    requestType: String,
    eventKind: Int?,
    decision: String,
    timestamp: Long,
    wasAutomatic: Boolean
): String {
    val content = "${previousHash ?: ""}|$callerPackage|$requestType|${eventKind ?: ""}|$decision|$timestamp|$wasAutomatic"
    val hmacKey = Nip55Database.getHmacKey()
        ?: throw IllegalStateException("HMAC key not initialized - cannot compute audit entry hash")
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(hmacKey, "HmacSHA256"))
    val hashBytes = mac.doFinal(content.toByteArray(Charsets.UTF_8))
    return hashBytes.joinToString("") { "%02x".format(it) }
}

private fun constantTimeEquals(a: String?, b: String?): Boolean {
    if (a == null && b == null) return true
    if (a == null || b == null) return false
    return MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))
}
