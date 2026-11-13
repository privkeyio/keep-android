package io.privkey.keep

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.nip55.FrostSignTestSupport
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.SecureStorage
import io.privkey.keep.uniffi.ShareMetadataInfo
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class KillSwitchEngageTest {

    private class KillSwitchWriteFails(private val inner: SecureStorage) : SecureStorage by inner {
        override fun storeShareByKey(key: String, data: ByteArray, metadata: ShareMetadataInfo) {
            if (key == KILL_SWITCH_KEY) throw KeepMobileException.StorageException("write refused")
            inner.storeShareByKey(key, data, metadata)
        }
    }

    @Test
    fun anEngageThatDoesNotSaveIsReportedAsEngagedBecauseTheCoreRefusesSigning() = runBlocking {
        val mobile = KeepMobile(KillSwitchWriteFails(FrostSignTestSupport.noAuthStorage()))
        try {
            assertEquals(KillSwitchEngage.UNSAVED, engageKillSwitch(mobile))
            assertTrue("the core must read an unsaved engage as engaged", mobile.getKillSwitch())
        } finally {
            mobile.destroy()
        }
    }

    @Test
    fun anEngageThatSavesIsReportedAsSaved() = runBlocking {
        val mobile = KeepMobile(FrostSignTestSupport.noAuthStorage())
        try {
            assertEquals(KillSwitchEngage.SAVED, engageKillSwitch(mobile))
            assertTrue(mobile.getKillSwitch())
        } finally {
            mobile.setKillSwitch(false)
            mobile.destroy()
        }
    }

    private companion object {
        const val KILL_SWITCH_KEY = "__keep_kill_switch_v1"
    }
}
