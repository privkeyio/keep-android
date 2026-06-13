package io.privkey.keep.nip55

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.Nip55DeclaredPermission
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.nip55ParsePermissions
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Covers the Kotlin-side glue that turns a caller-declared permission bundle into
 * persisted grants: Rust parsing, the checkbox filter, and the grant + "allow"
 * audit entries that grantDeclaredBundle writes on the success path. The parser
 * itself is exhaustively tested in Rust; these tests pin the integration with
 * PermissionStore.
 */
@RunWith(AndroidJUnit4::class)
class Nip55PermissionsBundleIntegrationTest {

    private lateinit var database: Nip55Database
    private lateinit var store: PermissionStore

    private val callerId = "com.test.app"

    @Before
    fun setup() {
        database = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            Nip55Database::class.java
        ).allowMainThreadQueries().build()
        store = PermissionStore(database)
    }

    @After
    fun teardown() {
        database.close()
    }

    // Mirrors ApprovalScreen's checkbox filter.
    private fun checkedOnly(
        declared: List<Nip55DeclaredPermission>,
        checked: List<Boolean>
    ): List<Nip55DeclaredPermission> =
        declared.filterIndexed { i, _ -> checked.getOrElse(i) { false } }

    // Mirrors Nip55Activity.grantDeclaredBundle.
    private suspend fun grantBundle(
        declared: List<Nip55DeclaredPermission>,
        duration: PermissionDuration
    ) {
        declared.forEach { perm ->
            val grantResult = runCatching {
                store.grantPermission(callerId, perm.requestType, perm.kind, duration)
            }
            val auditAction = if (grantResult.isFailure) "allow_grant_failed" else "allow"
            store.logOperation(callerId, perm.requestType, perm.kind, auditAction, wasAutomatic = false)
        }
    }

    @Test
    fun checkedBundleEntriesPersistAsAllow() = runBlocking {
        val declared = nip55ParsePermissions(
            """[{"type":"sign_event","kind":1},{"type":"nip44_decrypt"}]"""
        )
        assertEquals(2, declared.size)

        grantBundle(declared, PermissionDuration.FOREVER)

        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision(callerId, Nip55RequestType.SIGN_EVENT, 1)
        )
        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision(callerId, Nip55RequestType.NIP44_DECRYPT, null)
        )

        // grantDeclaredBundle audits each granted entry as "allow".
        val audit = store.getAuditLog()
        assertEquals(2, audit.size)
        assertTrue(audit.all { it.decision == "allow" && it.callerPackage == callerId })
    }

    @Test
    fun uncheckedEntriesAreNotGranted() = runBlocking {
        val declared = nip55ParsePermissions(
            """[{"type":"sign_event","kind":1},{"type":"nip44_decrypt"}]"""
        )
        // User unchecks the decrypt entry.
        val granted = checkedOnly(declared, listOf(true, false))

        grantBundle(granted, PermissionDuration.FOREVER)

        assertEquals(
            PermissionDecision.ALLOW,
            store.getPermissionDecision(callerId, Nip55RequestType.SIGN_EVENT, 1)
        )
        assertNull(store.getPermissionDecision(callerId, Nip55RequestType.NIP44_DECRYPT, null))
    }

    @Test
    fun justThisTimeBundleDoesNotPersist() = runBlocking {
        val declared = nip55ParsePermissions("""[{"type":"sign_event","kind":1}]""")

        grantBundle(declared, PermissionDuration.JUST_THIS_TIME)

        assertNull(store.getPermissionDecision(callerId, Nip55RequestType.SIGN_EVENT, 1))
    }

    @Test
    fun sensitiveKindBundleClampsForeverDuration() = runBlocking {
        // kind 4 (encrypted DM) is sensitive; FOREVER must clamp to an expiry.
        val declared = nip55ParsePermissions("""[{"type":"sign_event","kind":4}]""")
        assertEquals(1, declared.size)

        grantBundle(declared, PermissionDuration.FOREVER)

        val permissions = store.getPermissionsForCaller(callerId)
        assertEquals(1, permissions.size)
        assertNotNull(permissions[0].expiresAt)
    }

    @Test
    fun malformedBundleGrantsNothing() = runBlocking {
        val declared = nip55ParsePermissions("not json")
        assertTrue(declared.isEmpty())

        grantBundle(declared, PermissionDuration.FOREVER)

        assertTrue(store.getAllPermissions().isEmpty())
    }
}
