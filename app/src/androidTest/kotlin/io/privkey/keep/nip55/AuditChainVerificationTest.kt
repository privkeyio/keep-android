package io.privkey.keep.nip55

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.storage.KeystoreEncryptedPrefs
import io.privkey.keep.storage.corruptStoredValue
import io.privkey.keep.storage.forgetWriteProbe
import io.privkey.keep.storage.writeAndFindStoredName
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * DESTRUCTIVE: this suite operates on the production audit log. verifyAuditChain
 * reads the Keystore-backed HMAC key and audit anchor wired up only by
 * Nip55Database.getInstance, so setup/teardown call PermissionStore.clearAuditLog()
 * on the real on-device database. Running these tests wipes any existing audit-log
 * entries on the device/emulator. Do not point this at a device whose audit log
 * you need to keep.
 */
@RunWith(AndroidJUnit4::class)
class AuditChainVerificationTest {

    private lateinit var database: Nip55Database
    private lateinit var store: PermissionStore

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before
    fun setup() = runBlocking {
        // Must use the production singleton, not Room.inMemoryDatabaseBuilder like the
        // sibling store tests: getInstance is what wires up the Keystore-backed HMAC key
        // and audit anchor that verifyAuditChain reads. An in-memory DB has neither.
        database = Nip55Database.getInstance(context)
        store = PermissionStore(database)
        store.clearAuditLog()
    }

    @After
    fun teardown() = runBlocking {
        // Rewrites all four anchor entries readably, which is what undoes the staged
        // faults below.
        if (::store.isInitialized) store.clearAuditLog()
        forgetWriteProbe(context, DB_PREFS)
    }

    /**
     * Stages the fault the anchor reads could not distinguish: an entry that is on disk
     * and will not decrypt.
     *
     * Names are stored hashed, so the entry is identified by being the one a write adds,
     * which means dropping it first. [rewrite] has to put back what was there, since the
     * anchor is read as a pair.
     */
    private fun corruptStored(key: String, rewrite: () -> Unit) {
        KeystoreEncryptedPrefs.create(context, DB_PREFS).edit().remove(key).commit()
        corruptStoredValue(context, DB_PREFS, writeAndFindStoredName(context, DB_PREFS, rewrite))
    }

    @Test
    fun logOperationProducesVerifiableChain() = runBlocking {
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = true)
        store.logOperation("com.test.app", Nip55RequestType.GET_PUBLIC_KEY, null, "allow", wasAutomatic = false)
        store.logOperation("com.other.app", Nip55RequestType.SIGN_EVENT, 4, "deny", wasAutomatic = false)

        assertEquals(3, store.getAuditLog(10).size)
        assertEquals(ChainVerificationResult.Valid, store.verifyAuditChain())
    }

    @Test
    fun keyExportProducesVerifiableChain() = runBlocking {
        store.logKeyExport(AUDIT_OP_EXPORT_NCRYPTSEC)
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        store.logKeyExport(AUDIT_OP_EXPORT_SHARE)

        val entries = store.getAuditLog(10)
        assertEquals(3, entries.size)
        // The self-initiated export entries chain in with the same tamper-evident HMAC.
        assertEquals(ChainVerificationResult.Valid, store.verifyAuditChain())
        val exports = entries.filter { it.callerPackage == SELF_CALLER }
        assertEquals(2, exports.size)
        assertTrue(exports.any { it.requestType == AUDIT_OP_EXPORT_NCRYPTSEC })
        assertTrue(exports.any { it.requestType == AUDIT_OP_EXPORT_SHARE })
    }

    @Test
    fun tamperedAuditRowBreaksChain() = runBlocking {
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = true)
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)

        assertEquals(ChainVerificationResult.Valid, store.verifyAuditChain())

        // Tamper a MIDDLE row, not the tail: the flagged id must then differ from the
        // latest id, so this proves the walk pinpoints the corrupted entry rather than
        // just echoing the chain tail. Mutate it out-of-band (bypassing the write seam,
        // leaving its stale entryHash) so the Rust walk recomputes a mismatch; the
        // unchanged tail keeps the anchor consistent, so detection can only come from
        // the Rust HMAC walk, whose flagged id resolveChainVerification returns verbatim.
        val rows = store.getAuditLog(10).sortedBy { it.id }
        val tampered = rows[rows.size / 2]
        database.openHelper.writableDatabase.execSQL(
            "UPDATE nip55_audit_log SET decision = 'deny' WHERE id = ?",
            arrayOf<Any?>(tampered.id)
        )

        val flaggedId = when (val result = store.verifyAuditChain()) {
            is ChainVerificationResult.Tampered -> result.entryId
            is ChainVerificationResult.Broken -> result.entryId
            else -> throw AssertionError("expected Tampered/Broken but was $result")
        }
        assertEquals(tampered.id, flaggedId)
        // Guard that this really tampered a non-tail row, so the assertion above proves
        // pinpointing and not a tail-id echo.
        assertTrue(tampered.id != rows.last().id)
    }

    @Test
    fun anUnreadableAnchorCountIsTamperRatherThanAnUnpinnedChain() = runBlocking {
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        assertEquals(ChainVerificationResult.Valid, store.verifyAuditChain())
        val count = store.getAuditLogCount().toLong()

        corruptStored(KEY_ANCHOR_COUNT) {
            KeystoreEncryptedPrefs.create(context, DB_PREFS).edit().putLong(KEY_ANCHOR_COUNT, count).commit()
        }

        // Read as an absence this is an install with no anchor yet, which is seeded from
        // whatever the table holds. An attacker who truncates the table and corrupts this
        // one entry would have the remains anchored as the whole history.
        val result = store.verifyAuditChain()
        assertTrue("expected Tampered but was $result", result is ChainVerificationResult.Tampered)
    }

    @Test
    fun anUnreadableTamperFlagIsTamperRatherThanNoEvidence() = runBlocking {
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        assertEquals(ChainVerificationResult.Valid, store.verifyAuditChain())

        // Corrupted while it reads false, which is where the sticky flag sits until
        // something sets it. Reading it as its default is how evidence already recorded
        // gets dropped by the same access that recorded it.
        corruptStored(KEY_TAMPER) {
            KeystoreEncryptedPrefs.create(context, DB_PREFS).edit().putBoolean(KEY_TAMPER, false).commit()
        }

        val result = store.verifyAuditChain()
        assertTrue("expected Tampered but was $result", result is ChainVerificationResult.Tampered)
    }

    @Test
    fun anUnreadableClearMarkerDoesNotCompleteAClearNobodyRequested() = runBlocking {
        // The deliberate asymmetry: this one marker keeps its default when it will not
        // decrypt. Reading it as a pending clear resets the anchor against an empty
        // table, which is exactly the state a full truncation leaves and the only state
        // where the anchor still holds the evidence of it.
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        database.openHelper.writableDatabase.execSQL("DELETE FROM nip55_audit_log")
        corruptStored(KEY_CLEAR_PENDING) {
            KeystoreEncryptedPrefs.create(context, DB_PREFS).edit().putBoolean(KEY_CLEAR_PENDING, true).commit()
        }

        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)

        val result = store.verifyAuditChain()
        assertTrue("expected Tampered but was $result", result is ChainVerificationResult.Tampered)
    }

    private fun removeStored(vararg keys: String) {
        val editor = KeystoreEncryptedPrefs.create(context, DB_PREFS).edit()
        keys.forEach { editor.remove(it) }
        editor.commit()
    }

    @Test
    fun anUnreadableAnchorHashIsTamperRatherThanAnEmptyTail() = runBlocking {
        // The read whose old default was "", which pinned a bogus anchor with a real
        // count rather than reporting that the tail could not be read.
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        assertEquals(ChainVerificationResult.Valid, store.verifyAuditChain())
        val tail = store.getAuditLog(10).sortedBy { it.id }.last().entryHash

        corruptStored(KEY_ANCHOR_HASH) {
            KeystoreEncryptedPrefs.create(context, DB_PREFS).edit().putString(KEY_ANCHOR_HASH, tail).commit()
        }

        val result = store.verifyAuditChain()
        assertTrue("expected Tampered but was $result", result is ChainVerificationResult.Tampered)
    }

    @Test
    fun anUnreadableClearMarkerIsRecordedInTheStickyFlag() = runBlocking {
        // The marker is not acted on as a pending clear, but the fault is still written
        // down, and the verify pass is where this one is seen: nothing else in the file
        // ever rewrites that entry.
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        corruptStored(KEY_CLEAR_PENDING) {
            KeystoreEncryptedPrefs.create(context, DB_PREFS).edit().putBoolean(KEY_CLEAR_PENDING, false).commit()
        }

        val result = store.verifyAuditChain()
        assertTrue("expected Tampered but was $result", result is ChainVerificationResult.Tampered)
        assertTrue("the fault has to be recorded where it is sticky", Nip55Database.readAuditAnchorState().flagged)
    }

    @Test
    fun theEvidenceOutlivesTheEntryThatCarriedIt() = runBlocking {
        // One write observes the corrupted anchor and records it in the sticky flag,
        // after which the anchor advance replaces the corrupted entry with a readable
        // one. Deleting the anchor outright then reads as a fresh install, and only the
        // flag still says otherwise.
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        val count = store.getAuditLogCount().toLong()
        corruptStored(KEY_ANCHOR_COUNT) {
            KeystoreEncryptedPrefs.create(context, DB_PREFS).edit().putLong(KEY_ANCHOR_COUNT, count).commit()
        }

        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        removeStored(KEY_ANCHOR_COUNT, KEY_ANCHOR_HASH)

        val result = store.verifyAuditChain()
        assertTrue("expected Tampered but was $result", result is ChainVerificationResult.Tampered)
    }

    @Test
    fun aFaultSurvivesTheResetThatFinishesAnInterruptedClear() = runBlocking {
        // A clear whose anchor reset was lost to a crash leaves a readable pending marker
        // over an empty table, and the reconcile that finishes it rewrites all four
        // entries readably. A fault seen by the read before it has to outlive that, or
        // the reconcile erases the only evidence of it before anything records it.
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        database.openHelper.writableDatabase.execSQL("DELETE FROM nip55_audit_log")
        corruptStored(KEY_TAMPER) {
            KeystoreEncryptedPrefs.create(context, DB_PREFS).edit().putBoolean(KEY_TAMPER, false).commit()
        }
        Nip55Database.setAuditClearPending()

        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)

        assertTrue(
            "the reset rewrote the entry that carried the fault, so only the flag is left",
            Nip55Database.readAuditAnchorState().flagged
        )
    }

    @Test
    fun anInstallWithNoAnchorAtAllStillSeedsRatherThanFlagging() = runBlocking {
        // The benign direction, and the regression this change could most plausibly
        // cause in the field: an install that predates the anchor has a populated table
        // and none of the four entries, and has to be seeded rather than flagged.
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        removeStored(KEY_ANCHOR_COUNT, KEY_ANCHOR_HASH, KEY_TAMPER, KEY_CLEAR_PENDING)

        assertEquals(ChainVerificationResult.Valid, store.verifyAuditChain())

        val seeded = Nip55Database.readAuditAnchorState()
        assertEquals(2L, seeded.anchor?.entryCount)
        assertEquals(store.getAuditLog(10).sortedBy { it.id }.last().entryHash, seeded.anchor?.latestEntryHash)
    }

    private companion object {
        // Mirrors of the names PermissionDatabase stores these under. A rename there
        // leaves the fault staged on an entry nothing reads, which fails these loudly.
        const val DB_PREFS = "nip55_db_prefs"
        const val KEY_ANCHOR_COUNT = "audit_anchor_count"
        const val KEY_ANCHOR_HASH = "audit_anchor_hash"
        const val KEY_TAMPER = "audit_tamper_detected"
        const val KEY_CLEAR_PENDING = "audit_clear_pending"
    }
}
