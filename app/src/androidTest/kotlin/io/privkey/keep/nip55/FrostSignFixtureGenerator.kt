package io.privkey.keep.nip55

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.uniffi.KeepMobile
import org.junit.After
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FrostSignFixtureGenerator {

    private var mobile: KeepMobile? = null

    @After
    fun tearDown() {
        mobile?.destroy()
        mobile = null
    }

    @Test
    fun generateSharePair() {
        val manual = InstrumentationRegistry.getArguments().getString(FrostSignFixture.MANUAL_ARG)
        assumeTrue("manual-only generator; pass -e ${FrostSignFixture.MANUAL_ARG} 1", manual == "1")

        val storage = FrostSignTestSupport.noAuthStorage()
        val mobile = KeepMobile(storage).also { this.mobile = it }

        val result = mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "test", FrostSignFixture.PASSPHRASE)

        Log.i(TAG, "GROUP_PUBKEY=${result.groupPubkey}")
        println("GROUP_PUBKEY=${result.groupPubkey}")
        result.shares.forEach { share ->
            Log.i(TAG, "SHARE index=${share.shareIndex} EXPORT_DATA=${share.exportData}")
            println("SHARE index=${share.shareIndex} EXPORT_DATA=${share.exportData}")
        }
    }

    companion object {
        private const val TAG = "FrostSignFixtureGen"
    }
}
