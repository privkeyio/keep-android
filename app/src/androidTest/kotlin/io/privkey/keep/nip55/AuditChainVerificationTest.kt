package io.privkey.keep.nip55

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
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

    @Before
    fun setup() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        // Must use the production singleton, not Room.inMemoryDatabaseBuilder like the
        // sibling store tests: getInstance is what wires up the Keystore-backed HMAC key
        // and audit anchor that verifyAuditChain reads. An in-memory DB has neither.
        database = Nip55Database.getInstance(context)
        store = PermissionStore(database)
        store.clearAuditLog()
    }

    @After
    fun teardown() = runBlocking {
        if (::store.isInitialized) store.clearAuditLog()
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
}
