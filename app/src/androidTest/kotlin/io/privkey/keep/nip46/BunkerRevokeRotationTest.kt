package io.privkey.keep.nip46

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.nip55.FrostSignFixture
import io.privkey.keep.nip55.FrostSignTestSupport
import io.privkey.keep.uniffi.BunkerApprovalRequest
import io.privkey.keep.uniffi.BunkerApprovalResult
import io.privkey.keep.uniffi.BunkerCallbacks
import io.privkey.keep.uniffi.BunkerHandler
import io.privkey.keep.uniffi.BunkerLogEvent
import io.privkey.keep.uniffi.BunkerRememberDuration
import io.privkey.keep.uniffi.ConnectAuthorization
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.ParsedBunkerUrl
import io.privkey.keep.uniffi.parseBunkerUrl
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Revoking a client replaces the connect secret, and a rotation the bunker key too, even
 * when the bunker service is not running, so a revoked client that kept the old bunker URL
 * cannot connect again with it.
 * Starts a real bunker against a public relay, so it is manual-only like the FROST tests,
 * and it rotates the test device's own bunker URL.
 */
@RunWith(AndroidJUnit4::class)
class BunkerRevokeRotationTest {

    private var mobile: KeepMobile? = null

    @After
    fun tearDown() {
        mobile?.destroy()
        mobile = null
    }

    @Test(timeout = 180_000L)
    fun rotatingWithTheServiceStoppedRetiresTheOldBunkerUrl() = runBlocking {
        val mobile = setUpMobile()

        val before = startedBunkerUrl(mobile)
        assertNotNull("the bunker URL must carry a connect secret", before.secret)
        // A restart alone keeps the URL, so the change below comes from the rotation.
        val restarted = startedBunkerUrl(mobile)
        assertEquals(before.secret, restarted.secret)
        assertEquals(before.pubkey, restarted.pubkey)

        BunkerService.rotateBunkerCredentials(mobile)
        assertNull("the rotation must not have needed the service", BunkerService.current())

        val after = startedBunkerUrl(mobile)
        assertNotNull(after.secret)
        assertNotEquals("the old connect secret must be retired", before.secret, after.secret)
        assertNotEquals("the old bunker key must be retired", before.pubkey, after.pubkey)
    }

    @Test(timeout = 180_000L)
    fun revokingWithTheServiceStoppedRetiresTheSecretAndKeepsTheBunkerKey() = runBlocking {
        val mobile = setUpMobile()
        val context = InstrumentationRegistry.getInstrumentation().targetContext

        val before = startedBunkerUrl(mobile)
        BunkerService.revokeClients(context, mobile, listOf("cd".repeat(32)))
        assertNull("the revoke must not have needed the service", BunkerService.current())

        val after = startedBunkerUrl(mobile)
        assertNotNull(after.secret)
        assertNotEquals("the old connect secret must be retired", before.secret, after.secret)
        assertEquals("other clients keep the bunker key", before.pubkey, after.pubkey)
    }

    @Test(timeout = 180_000L)
    fun aClientRevokedBeforeThisVersionGetsTheUrlRotatedOnce() {
        val mobile = setUpMobile()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val markers = context.getSharedPreferences(BunkerService.BUNKER_MARKERS_PREFS, Context.MODE_PRIVATE)
        val probe = "ab".repeat(32)
        val saved = Nip46ClientStore.getDenylist(context)
        try {
            markers.edit().remove(BunkerService.KEY_ROTATED_FOR_EARLIER_REVOKES).commit()
            Nip46ClientStore.setDenylistForTest(context, saved + probe)

            val before = startedBunkerUrl(mobile)
            assertTrue(BunkerService.rotateOnceForEarlierRevokes(context, mobile))
            val after = startedBunkerUrl(mobile)
            assertNotEquals(before.secret, after.secret)
            assertNotEquals(before.pubkey, after.pubkey)

            assertFalse("the rotation happens once", BunkerService.rotateOnceForEarlierRevokes(context, mobile))
            assertEquals(after.secret, startedBunkerUrl(mobile).secret)
        } finally {
            Nip46ClientStore.setDenylistForTest(context, saved)
        }
    }

    @Test(timeout = 180_000L)
    fun withNothingRevokedTheUrlIsLeftAlone() {
        val mobile = setUpMobile()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assumeTrue("the device denylist must be empty", Nip46ClientStore.getDenylist(context).isEmpty())
        context.getSharedPreferences(BunkerService.BUNKER_MARKERS_PREFS, Context.MODE_PRIVATE)
            .edit().remove(BunkerService.KEY_ROTATED_FOR_EARLIER_REVOKES).commit()

        val before = startedBunkerUrl(mobile)
        assertFalse(BunkerService.rotateOnceForEarlierRevokes(context, mobile))
        assertEquals(before.secret, startedBunkerUrl(mobile).secret)
    }

    private fun setUpMobile(): KeepMobile {
        val manual = InstrumentationRegistry.getArguments().getString(FrostSignFixture.MANUAL_ARG)
        assumeTrue("manual-only test; pass -e ${FrostSignFixture.MANUAL_ARG} 1", manual == "1")
        assumeTrue("the bunker service must not be running", BunkerService.current() == null)
        val storage = FrostSignTestSupport.noAuthStorage()
        val mobile = KeepMobile(storage).also { this.mobile = it }
        FrostSignTestSupport.importShareNoAuth(mobile, storage, FrostSignFixture.SHARE1_EXPORT_DATA, "bunker-rotate-setup")
        FrostSignTestSupport.initializeWithDecryptContext(mobile, storage, "bunker-rotate-connect")
        return mobile
    }

    private fun startedBunkerUrl(mobile: KeepMobile): ParsedBunkerUrl =
        BunkerHandler(mobile).use { handler ->
            try {
                handler.startBunker(listOf(FrostSignFixture.RELAY), RejectAll)
                parseBunkerUrl(requireNotNull(handler.getBunkerUrl()) { "a started bunker must publish its URL" })
            } finally {
                handler.stopBunker()
            }
        }

    private object RejectAll : BunkerCallbacks {
        override fun onLog(event: BunkerLogEvent) = Unit
        override fun requestApproval(request: BunkerApprovalRequest) =
            BunkerApprovalResult(approved = false, remember = BunkerRememberDuration.JUST_THIS_TIME)
        override fun onConnect(pubkey: String, name: String, authorization: ConnectAuthorization) = Unit
    }
}
