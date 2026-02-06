package io.privkey.keep.nip55

import android.content.Context
import androidx.room.*
import androidx.room.migration.Migration
import io.privkey.keep.storage.KeystoreEncryptedPrefs
import io.privkey.keep.storage.LegacyPrefsMigration
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import java.security.SecureRandom

@Database(entities = [Nip55Permission::class, Nip55AuditLog::class, Nip55AppSettings::class, VelocityEntry::class], version = 7)
abstract class Nip55Database : RoomDatabase() {
    abstract fun permissionDao(): Nip55PermissionDao
    abstract fun auditLogDao(): Nip55AuditLogDao
    abstract fun appSettingsDao(): Nip55AppSettingsDao
    abstract fun velocityDao(): VelocityDao

    companion object {
        init {
            System.loadLibrary("sqlcipher")
        }

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

        private val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL("UPDATE nip55_permissions SET eventKind = -1 WHERE eventKind IS NULL")
                db.execSQL("UPDATE nip55_audit_log SET eventKind = -1 WHERE eventKind IS NULL")
                db.execSQL("UPDATE velocity_tracker SET eventKind = -1 WHERE eventKind IS NULL")
            }
        }

        private val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE nip55_permissions ADD COLUMN createdAtElapsed INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE nip55_permissions ADD COLUMN durationMs INTEGER")
                db.execSQL("ALTER TABLE nip55_app_settings ADD COLUMN createdAtElapsed INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE nip55_app_settings ADD COLUMN durationMs INTEGER")
            }
        }

        private val MIGRATION_6_7 = object : Migration(6, 7) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL("CREATE INDEX IF NOT EXISTS index_nip55_audit_log_callerPackage_eventKind ON nip55_audit_log(callerPackage, eventKind)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_nip55_audit_log_callerPackage_timestamp ON nip55_audit_log(callerPackage, timestamp)")
            }
        }

        private val MIGRATIONS = arrayOf(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7)

        private fun getEncryptedPrefs(context: Context) =
            KeystoreEncryptedPrefs.create(context, PREFS_NAME)

        private fun getOrCreateKey(context: Context, prefKey: String, commit: Boolean = false): ByteArray {
            val prefs = getEncryptedPrefs(context)

            var existing = prefs.getString(prefKey, null)
            if (existing != null) {
                return android.util.Base64.decode(existing, android.util.Base64.NO_WRAP)
            }

            existing = LegacyPrefsMigration.migrateStringIfNeeded(context, PREFS_NAME, prefKey, prefs)
            if (existing != null) {
                return android.util.Base64.decode(existing, android.util.Base64.NO_WRAP)
            }

            val newKey = ByteArray(32).apply { SecureRandom().nextBytes(this) }
            val editor = prefs.edit().putString(prefKey, android.util.Base64.encodeToString(newKey, android.util.Base64.NO_WRAP))
            if (commit) editor.commit() else editor.apply()
            return newKey
        }

        private fun getOrCreateDbKey(context: Context): ByteArray =
            getOrCreateKey(context, KEY_DB_PASSPHRASE)

        private fun getOrCreateHmacKey(context: Context): ByteArray {
            hmacKey?.let { return it }
            return getOrCreateKey(context, KEY_HMAC_SECRET, commit = true).also { hmacKey = it }
        }

        fun getHmacKey(): ByteArray? = hmacKey

        fun getInstance(context: Context): Nip55Database {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: run {
                    val passphrase = getOrCreateDbKey(context.applicationContext)
                    getOrCreateHmacKey(context.applicationContext)
                    val factory = SupportOpenHelperFactory(passphrase)
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
