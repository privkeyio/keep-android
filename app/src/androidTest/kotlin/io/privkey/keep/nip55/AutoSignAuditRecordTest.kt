package io.privkey.keep.nip55

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * DESTRUCTIVE: these tests append to, and clear, the production audit log on the
 * device, for the same reason the sibling chain test does: the Keystore-backed
 * HMAC key and the audit anchor are wired up by the database singleton, and an
 * append against an anchor another suite has moved sets a sticky tamper flag
 * that outlives the run. Do not point this at a device whose audit log matters.
 *
 * An auto-signed request is answered without the user present, so its audit row
 * is the only record it ever happened, and the frequency input of later
 * decisions is counted from those same rows. The row is therefore a condition of
 * returning the signature rather than a side effect attempted after it, and the
 * append has to report what it actually did.
 *
 * The append does not go through the provider's permit wrapper, which is how it
 * came to be skipped without anything raising or being logged: that wrapper
 * takes a permit before it does anything, and contention alone could mean no
 * attempt was made. It runs on its own scope under a budget instead, so a
 * stalled write cannot hold the caller either.
 *
 * What is not covered here, by design rather than omission: the provider refuses
 * a same-uid caller, so instrumentation cannot drive a request through it end to
 * end, and the one line that turns a false into an error cursor is verified by
 * reading. The cross-process harness is where that path is exercised.
 */
@RunWith(AndroidJUnit4::class)
class AutoSignAuditRecordTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private lateinit var database: Nip55Database
    private lateinit var store: PermissionStore

    @Before
    fun startFromAClearedChain() = runBlocking {
        // The production singleton, not an in-memory database: it is what carries
        // the anchor and the HMAC key an append advances, and an in-memory one
        // would move that shared anchor away from the chain it belongs to.
        database = Nip55Database.getInstance(context)
        store = PermissionStore(database)
        store.clearAuditLog()
    }

    @After
    fun leaveTheChainClear() = runBlocking { store.clearAuditLog() }

    // The ordinary path: the row lands and the append says so, which is what the
    // caller is allowed to return a signature on.
    @Test
    fun anAppendThatLandsReportsSuccessAndWritesTheRow() {
        val provider = Nip55ContentProvider()

        val recorded = provider.recordAutoSigned(store, CALLER, Nip55RequestType.SIGN_EVENT, 1)

        assertTrue("an append that landed must report success", recorded)
        assertEquals("and must have written exactly one row", 1, runBlocking { store.getAuditLogCount() })
    }

    // The case the gate exists for: the append cannot be made, so it must report
    // that rather than the absence of a complaint.
    //
    // Staged on a throwaway database rather than the real one, because closing
    // the singleton would fail every audit write in the process after it. The
    // append raises where it would have written, and because it raises before
    // the row and before the anchor advance, this leaves the shared anchor
    // exactly where it found it.
    @Test
    fun anAppendThatCannotBeMadeReportsFailure() {
        val doomed = Room.inMemoryDatabaseBuilder(context, Nip55Database::class.java)
            .allowMainThreadQueries()
            .build()
        val overAClosedDatabase = PermissionStore(doomed)
        doomed.close()

        val recorded = Nip55ContentProvider()
            .recordAutoSigned(overAClosedDatabase, CALLER, Nip55RequestType.SIGN_EVENT, 1)

        assertFalse("an append that could not be made must not report success", recorded)
        assertEquals(
            "and the real chain must be untouched",
            0,
            runBlocking { store.getAuditLogCount() }
        )
    }

    // A decision that refused is recorded the same way. Nothing was released, so
    // the result is not a gate, but the row still has to land: the frequency
    // input of later assessments counts rows whatever they decided.
    @Test
    fun aRefusedDecisionIsRecordedTheSameWay() {
        val provider = Nip55ContentProvider()

        val recorded = provider.recordAutoDecision(
            store, CALLER, Nip55RequestType.SIGN_EVENT, 1, "deny_velocity"
        )

        assertTrue("a refused decision must be recorded", recorded)
        assertEquals("and must have written exactly one row", 1, runBlocking { store.getAuditLogCount() })
    }

    // An append whose caller has stopped waiting is turned away under the writer's
    // lock: nothing is written and the chain still verifies.
    @Test
    fun anAppendRefusedItsClaimWritesNothing() = runBlocking {
        val written = store.logOperation(
            CALLER, Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = true, claim = { false }
        )

        assertFalse("a refused claim must report nothing written", written)
        assertEquals("and must leave no row", 0, store.getAuditLogCount())
        assertTrue("a later append still lands", store.logOperation(CALLER, Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = true))
        assertEquals(1, store.getAuditLogCount())
        assertEquals("and the chain verifies", ChainVerificationResult.Valid, store.verifyAuditChain())
    }

    private companion object {
        const val CALLER = "io.privkey.keep.test.autosign.audit"
    }
}
