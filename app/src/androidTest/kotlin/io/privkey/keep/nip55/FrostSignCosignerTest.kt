package io.privkey.keep.nip55

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.KeepMobile
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FrostSignCosignerTest {

    private var mobile: KeepMobile? = null

    @After
    fun tearDown() {
        mobile?.destroy()
        mobile = null
    }

    @Test
    fun coSign_pendingRequests_forBoundedDuration() {
        val manual = InstrumentationRegistry.getArguments().getString(FrostSignFixture.MANUAL_ARG)
        assumeTrue("manual-only test; pass -e ${FrostSignFixture.MANUAL_ARG} 1", manual == "1")
        assumeTrue("SHARE2_EXPORT_DATA not filled in", FrostSignFixture.SHARE2_EXPORT_DATA.isNotEmpty())

        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val storage = AndroidKeystoreStorage(context, requireUserAuth = false)
        val mobile = KeepMobile(storage).also { this.mobile = it }

        FrostSignTestSupport.importShareNoAuth(mobile, storage, FrostSignFixture.SHARE2_EXPORT_DATA, "cosign-setup")
        FrostSignTestSupport.initializeWithDecryptContext(mobile, storage, "cosign-connect")
        FrostSignTestSupport.assertFixtureShareLoaded(mobile)

        assertFalse("Kill switch must be disabled to co-sign", mobile.getKillSwitch())

        val deadline = System.currentTimeMillis() + POLL_DURATION_MS
        while (System.currentTimeMillis() < deadline) {
            for (req in mobile.getPendingRequests()) {
                Log.i(TAG, "Approving request id=${req.id} type=${req.messageType}")
                mobile.approveRequest(req.id)
            }
            Thread.sleep(POLL_INTERVAL_MS)
        }
    }

    companion object {
        private const val TAG = "FrostSignCosigner"
        private const val POLL_DURATION_MS = 180_000L
        private const val POLL_INTERVAL_MS = 500L
    }
}
