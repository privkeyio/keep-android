package io.privkey.keep.nip55

import android.content.Context
import androidx.room.*
import androidx.room.migration.Migration
import io.privkey.keep.storage.KeystoreEncryptedPrefs
import io.privkey.keep.storage.LegacyPrefsMigration
import io.privkey.keep.storage.PrefRead
import io.privkey.keep.storage.ReadablePrefs
import io.privkey.keep.uniffi.KeepMobileException
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import java.security.SecureRandom

@Database(entities = [Nip55Permission::class, Nip55AuditLog::class, Nip55AppSettings::class, VelocityEntry::class, EventLogEntry::class], version = 10)
abstract class Nip55Database : RoomDatabase() {
    abstract fun permissionDao(): Nip55PermissionDao
    abstract fun auditLogDao(): Nip55AuditLogDao
    abstract fun appSettingsDao(): Nip55AppSettingsDao
    abstract fun velocityDao(): VelocityDao
    abstract fun eventLogDao(): EventLogDao

    companion object {
        init {
            System.loadLibrary("sqlcipher")
        }

        @Volatile
        private var INSTANCE: Nip55Database? = null

        private const val PREFS_NAME = "nip55_db_prefs"
        private const val DB_NAME = "nip55_permissions.db"
        private const val KEY_DB_PASSPHRASE = "db_passphrase"
        private const val KEY_HMAC_SECRET = "hmac_secret"
        private const val KEY_AUDIT_ANCHOR_HASH = "audit_anchor_hash"
        private const val KEY_AUDIT_ANCHOR_COUNT = "audit_anchor_count"
        private const val KEY_AUDIT_TAMPER = "audit_tamper_detected"
        private const val KEY_AUDIT_CLEAR_PENDING = "audit_clear_pending"

        @Volatile
        private var hmacKey: ByteArray? = null

        @Volatile
        private var appContext: Context? = null

        @Volatile
        private var auditPrefs: ReadablePrefs? = null

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

        private val MIGRATION_7_8 = object : Migration(7, 8) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS event_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        timestamp INTEGER NOT NULL,
                        category TEXT NOT NULL,
                        level TEXT NOT NULL,
                        source TEXT NOT NULL DEFAULT '',
                        message TEXT NOT NULL DEFAULT ''
                    )
                """)
                db.execSQL("CREATE INDEX IF NOT EXISTS index_event_log_timestamp ON event_log(timestamp)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_event_log_category_timestamp ON event_log(category, timestamp)")
            }
        }

        // Adds the per-relay grant scope (NIP-42 / kind 22242). The relay column
        // defaults to '' so every existing grant becomes a non-relay/wildcard grant
        // (backward-compatible), and the unique index is widened to include relay so
        // grants for the same (caller, type, kind) on different relays can coexist.
        private val MIGRATION_8_9 = object : Migration(8, 9) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE nip55_permissions ADD COLUMN relay TEXT NOT NULL DEFAULT ''")
                // Existing kind-22242 grants were blanket (any relay). Promote them to
                // the explicit all-relays wildcard so they keep auto-approving after the
                // lookup becomes relay-scoped (relay-specific -> '*'); new grants default
                // to the specific relay. All other grants keep relay='' (not meaningful).
                db.execSQL("UPDATE nip55_permissions SET relay = '*' WHERE requestType = 'SIGN_EVENT' AND eventKind = 22242")
                db.execSQL("DROP INDEX IF EXISTS index_nip55_permissions_callerPackage_requestType_eventKind")
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_nip55_permissions_callerPackage_requestType_eventKind_relay ON nip55_permissions(callerPackage, requestType, eventKind, relay)")
            }
        }

        // Nullable, with no default: an existing row carries no request id, and the
        // hash of a row without one is unchanged, so every existing row still verifies.
        private val MIGRATION_9_10 = object : Migration(9, 10) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE nip55_audit_log ADD COLUMN requestId TEXT")
            }
        }

        private val MIGRATIONS = arrayOf(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7, MIGRATION_7_8, MIGRATION_8_9, MIGRATION_9_10)

        private fun getEncryptedPrefs(context: Context) =
            auditPrefs ?: synchronized(this) {
                auditPrefs ?: KeystoreEncryptedPrefs.create(context, PREFS_NAME).also { auditPrefs = it }
            }

        /**
         * The database passphrase or the audit HMAC secret, minted on a first run.
         *
         * A key that is stored and will not decrypt does not mint a replacement over
         * anything, because minting one is not a recovery: the database stays
         * encrypted under the old key, nothing here deletes or rebuilds it, and a fresh
         * passphrase cannot open it, so every later query fails with an opaque SQLite
         * error rather than this one naming the cause. That refusal comes from
         * [mintRefusal], which asks what a mint would destroy, rather than from the read
         * itself: a store holding nothing a mint can harm is better served by minting
         * than by raising, and the write sweeps whatever could not be read with it. The write would also replace the
         * stored ciphertext, which is what a restored Keystore alias would need. For the
         * audit HMAC the same mint would silently restart a tamper-evident chain.
         *
         * An absent key is refused the same way when [mintRefusal] names a reason, which
         * is where each caller holds the evidence that what the key protects already
         * exists. The passphrase refuses over a database file with content, because a
         * database that exists was encrypted under a key this is about to replace.
         * Deleting the entry produces this, and so does losing a queued write to process
         * death. An empty file is not refused: it holds nothing, so minting over it loses
         * nothing, and that is the state a first run can legitimately leave behind. The
         * audit secret cannot use that signal, since the file is non-empty from first use
         * onward whether or not any audit row was ever chained, so it refuses on the
         * audit anchor instead (see [auditChainExists]). The reason is read from the store
         * this resolved, so a test that redirects [prefsName] redirects it too.
         *
         * [prefsName] is open for tests, which cannot stage a fault in the shared store the
         * rest of the suite reads, and selects both the file and the store so the two
         * cannot disagree. [prefs] wraps whatever [prefsName] selected, for the one fault
         * a real store will not produce on demand: a write that reports failure.
         */
        @androidx.annotation.VisibleForTesting
        internal fun getOrCreateKey(
            context: Context,
            prefKey: String,
            prefsName: String = PREFS_NAME,
            prefs: ReadablePrefs? = null,
            mintRefusal: ((ReadablePrefs) -> String?)? = null,
        ): ByteArray {
            val store = prefs
                ?: if (prefsName == PREFS_NAME) getEncryptedPrefs(context)
                else KeystoreEncryptedPrefs.create(context, prefsName)

            when (val stored = store.readString(prefKey)) {
                // Decoding is inside the refusal: a value that decrypts and is not base64
                // is stored and unusable, which is the case this reports rather than
                // raising whatever the decoder happens to raise. Length is deliberately
                // not checked, since a key of another length is a key this has always
                // accepted and rejecting it now would close a database that opens today.
                is PrefRead.Found ->
                    return runCatching {
                        android.util.Base64.decode(stored.value, android.util.Base64.NO_WRAP)
                    }.getOrElse {
                        throw KeepMobileException.StorageException("Stored $prefKey could not be read")
                    }
                PrefRead.Absent -> Unit
                // Two different things read this way and they are not owed the
                // same answer. A value stored under this key's own name, which a
                // lost Keystore alias leaves undecryptable, is this store's and
                // is kept: minting over it would replace the key the database was
                // encrypted under, and the ciphertext surviving is what lets a
                // restored alias bring the database and the audit chain back. A
                // value the lookup refuses to read as this key's is not this
                // store's and may be a string anything able to write this
                // directory put at a name derived from constants in the build;
                // raising on that would brick an install that has nothing worth
                // protecting, where minting overwrites it and sweeps it.
                //
                // contains() separates them, because it answers through the
                // lookup's Found case alone: the stored one is Found and the
                // refused one is not.
                // A presence check resolves the name, which needs the derivation
                // key, so the fault that made the read unreadable can raise here
                // too. That failure proves nothing about what is stored, so it
                // is read as "something is", which keeps this path answering with
                // the exception it documents rather than a raw crypto one.
                PrefRead.Unreadable ->
                    if (runCatching { store.contains(prefKey) }.getOrDefault(true)) {
                        throw KeepMobileException.StorageException("Stored $prefKey could not be read")
                    }
            }

            val existing = LegacyPrefsMigration.migrateStringIfNeeded(context, prefsName, prefKey, store)
            if (existing != null) {
                return android.util.Base64.decode(existing, android.util.Base64.NO_WRAP)
            }

            mintRefusal?.invoke(store)?.let { throw KeepMobileException.StorageException(it) }

            val newKey = ByteArray(32).apply { SecureRandom().nextBytes(this) }
            // Both keys commit rather than apply, and the result is checked: a key handed
            // back without reaching disk is one the database gets created under and then
            // cannot be opened with, which is the state the refusal above makes permanent.
            val written = store.edit()
                .putString(prefKey, android.util.Base64.encodeToString(newKey, android.util.Base64.NO_WRAP))
                .commit()
            if (!written) {
                throw KeepMobileException.StorageException("Minted $prefKey could not be stored")
            }
            return newKey
        }

        // The write is committed and checked before Room can use the key, which still
        // narrows rather than closes the window: the preferences file is fsynced but the
        // directory holding it is not, so a commit that returned true can roll back. The
        // refusal above is what catches that.
        //
        // [dbName] is open for tests, so the path this derives is the one under test
        // rather than a file staged somewhere else.
        @androidx.annotation.VisibleForTesting
        internal fun getOrCreateDbKey(
            context: Context,
            prefsName: String = PREFS_NAME,
            dbName: String = DB_NAME,
        ): ByteArray =
            getOrCreateKey(context, KEY_DB_PASSPHRASE, prefsName = prefsName) { _ ->
                if (context.getDatabasePath(dbName).length() > 0L) {
                    "No stored $KEY_DB_PASSPHRASE for a database that exists"
                } else {
                    null
                }
            }

        // The anchor is read through the store this was handed rather than through
        // readAuditAnchorState, which answers from appContext: the mint runs inside
        // getInstance before that is assigned, so it would read an empty state and never
        // refuse. readLong rather than getLong, so a count that will not decrypt refuses
        // instead of reading as the absence that mints.
        //
        // [prefsName] is open for tests, which is also what keeps the companion-wide
        // hmacKey cache in the caller below rather than here: a test minting into prefs
        // of its own must not leave the rest of the process signing audit entries with
        // the key it produced.
        @androidx.annotation.VisibleForTesting
        internal fun getOrCreateAuditSecret(
            context: Context,
            prefsName: String = PREFS_NAME,
        ): ByteArray =
            getOrCreateKey(context, KEY_HMAC_SECRET, prefsName = prefsName) { store ->
                val chained = auditChainExists(
                    store.readLong(KEY_AUDIT_ANCHOR_COUNT),
                    store.readString(KEY_AUDIT_ANCHOR_HASH)
                )
                if (chained) "No stored $KEY_HMAC_SECRET for an audit chain that exists" else null
            }

        private fun getOrCreateHmacKey(context: Context): ByteArray {
            hmacKey?.let { return it }
            return getOrCreateAuditSecret(context).also { hmacKey = it }
        }

        fun getHmacKey(): ByteArray? = hmacKey

        // Audit tail anchor lives in the Keystore-backed encrypted prefs (same trust
        // tier as the HMAC key), out of reach of an attacker with Room write access.
        //
        // Read three-way, and in one call: the decision is over all three values, and
        // reporting a value that will not decrypt as the default it would have had is
        // what lets the anchor be re-pinned to a table that was truncated under it.
        internal fun readAuditAnchorState(): AuditAnchorState {
            // Set after both key reads in getInstance, so there is no anchor to read yet
            // rather than an unreadable one.
            val ctx = appContext
                ?: return AuditAnchorState(null, flagged = false, clearPending = false, unreadable = false)
            val prefs = getEncryptedPrefs(ctx)
            return resolveAuditAnchorState(
                prefs.readLong(KEY_AUDIT_ANCHOR_COUNT),
                prefs.readString(KEY_AUDIT_ANCHOR_HASH),
                prefs.readBoolean(KEY_AUDIT_TAMPER),
                prefs.readBoolean(KEY_AUDIT_CLEAR_PENDING)
            )
        }

        fun setAuditAnchor(anchor: AuditAnchor) {
            val ctx = appContext ?: return
            getEncryptedPrefs(ctx).edit()
                .putString(KEY_AUDIT_ANCHOR_HASH, anchor.latestEntryHash)
                .putLong(KEY_AUDIT_ANCHOR_COUNT, anchor.entryCount)
                .commit()
        }

        // Sticky evidence that the audit table was mutated out-of-band between two
        // sanctioned writes; once set it stays set until a full clearAuditLog reset.
        // Read with the anchor, in readAuditAnchorState.
        fun setAuditTamperDetected() {
            val ctx = appContext ?: return
            getEncryptedPrefs(ctx).edit().putBoolean(KEY_AUDIT_TAMPER, true).commit()
        }

        // Recoverable intent marker for clear(): the tail goes empty, which is otherwise
        // indistinguishable from total truncation, so a crash between the clear commit and
        // the anchor reset needs a Keystore-backed (attacker-unforgeable) breadcrumb to
        // prove the empty DB is a sanctioned clear rather than a wipe.
        //
        // Read with the anchor, in readAuditAnchorState, which is also where the one
        // asymmetry in these four reads is documented: a marker that will not decrypt is
        // recorded as a fault but is not acted on as a pending clear.
        fun setAuditClearPending() {
            val ctx = appContext ?: return
            getEncryptedPrefs(ctx).edit().putBoolean(KEY_AUDIT_CLEAR_PENDING, true).commit()
        }

        fun clearAuditClearPending() {
            val ctx = appContext ?: return
            getEncryptedPrefs(ctx).edit().putBoolean(KEY_AUDIT_CLEAR_PENDING, false).commit()
        }

        // Single commit so the anchor, the sticky flag and the clear-pending marker can
        // never diverge on reset.
        fun resetAuditAnchor() {
            val ctx = appContext ?: return
            getEncryptedPrefs(ctx).edit()
                .putString(KEY_AUDIT_ANCHOR_HASH, "")
                .putLong(KEY_AUDIT_ANCHOR_COUNT, 0L)
                .putBoolean(KEY_AUDIT_TAMPER, false)
                .putBoolean(KEY_AUDIT_CLEAR_PENDING, false)
                .commit()
        }

        fun getInstance(context: Context): Nip55Database {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: run {
                    val passphrase = getOrCreateDbKey(context.applicationContext)
                    getOrCreateHmacKey(context.applicationContext)
                    // After the reads, so a refusal does not leave the companion holding a
                    // context for an instance that was never built.
                    appContext = context.applicationContext
                    val factory = SupportOpenHelperFactory(passphrase)
                    Room.databaseBuilder(
                        context.applicationContext,
                        Nip55Database::class.java,
                        DB_NAME
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
