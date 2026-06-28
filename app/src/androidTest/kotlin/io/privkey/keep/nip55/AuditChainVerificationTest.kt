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

@RunWith(AndroidJUnit4::class)
class AuditChainVerificationTest {

    private lateinit var database: Nip55Database
    private lateinit var store: PermissionStore

    @Before
    fun setup() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Nip55Database.getInstance(context)
        store = PermissionStore(database)
        store.clearAuditLog()
    }

    @After
    fun teardown() = runBlocking {
        store.clearAuditLog()
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
    fun tamperedAuditRowBreaksChain() = runBlocking {
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = true)

        assertEquals(ChainVerificationResult.Valid, store.verifyAuditChain())

        // Mutate a persisted row out-of-band (bypassing the write seam, leaving its
        // stale entryHash) so the Rust walk recomputes a mismatch.
        val tampered = store.getAuditLog(10).first()
        database.openHelper.writableDatabase.execSQL(
            "UPDATE nip55_audit_log SET decision = 'deny' WHERE id = ?",
            arrayOf<Any?>(tampered.id)
        )

        val result = store.verifyAuditChain()
        assertTrue("expected Tampered/Broken but was $result", result is ChainVerificationResult.Tampered)
        assertEquals(tampered.id, (result as ChainVerificationResult.Tampered).entryId)
    }
}
