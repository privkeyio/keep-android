package io.privkey.keep.storage

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.ShareMetadataInfo
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * `pendingDkgShare()` has three outcomes and the UI has to tell them apart: a
 * marker is present, no marker exists, or the marker could not be read. Only
 * the first two are safe to render as state. Reporting an unreadable marker as
 * absent hides the recover/discard dialog while `frost_run_dkg` keeps
 * fail-closing on the same read, which leaves group creation blocked with no
 * reachable control to unblock it.
 *
 * These run against the real Keystore rather than a fake, because the failure
 * being pinned is a storage-layer read fault and a fake would decide the answer
 * the test is asking about.
 */
@RunWith(AndroidJUnit4::class)
class PendingDkgMarkerStateTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var storage: AndroidKeystoreStorage
    private lateinit var mobile: KeepMobile

    @Before fun setup() {
        storage = AndroidKeystoreStorage(context, requireUserAuth = false)
        mobile = KeepMobile(storage)
        clearMarker()
    }

    @After fun teardown() = clearMarker()

    private fun clearMarker() {
        runCatching { mobile.discardPendingDkgShare() }
    }

    private fun writeMarker(json: String) {
        storage.storeShareByKey(
            MARKER_KEY,
            json.toByteArray(Charsets.UTF_8),
            ShareMetadataInfo("dkg_pending", 0u, 0u, 0u, ByteArray(0), false)
        )
    }

    @Test fun absent_marker_reads_as_null() {
        assertNull(mobile.pendingDkgShare())
    }

    @Test fun stored_marker_is_returned() {
        writeMarker(VALID_MARKER)
        val pending = mobile.pendingDkgShare()
        assertNotNull(pending)
        assertEquals("Family Wallet", pending!!.name)
        assertEquals(true, pending.vaultProtected)
    }

    /**
     * The load path only maps `StorageNotFound` to "nothing pending". A marker
     * that is present but undeserializable must surface as a thrown error, not
     * as null: null is what makes the discard escape hatch unreachable.
     */
    @Test fun unreadable_marker_throws_rather_than_reading_as_absent() {
        writeMarker("{ this is not the marker json }")
        assertThrows(Exception::class.java) { mobile.pendingDkgShare() }
    }

    /** Discard is the escape hatch, so it has to work on a corrupt marker too. */
    @Test fun discard_clears_an_unreadable_marker() {
        writeMarker("{ this is not the marker json }")
        assertThrows(Exception::class.java) { mobile.pendingDkgShare() }
        mobile.discardPendingDkgShare()
        assertNull(mobile.pendingDkgShare())
    }

    @Test fun discard_clears_a_valid_marker() {
        writeMarker(VALID_MARKER)
        assertNotNull(mobile.pendingDkgShare())
        mobile.discardPendingDkgShare()
        assertNull(mobile.pendingDkgShare())
    }

    private companion object {
        const val MARKER_KEY = "__keep_dkg_pending_v1"
        const val VALID_MARKER =
            """{"schema_version":1,"name":"Family Wallet","group_pubkey_hex":"aa","vault_protected":true}"""
    }
}
