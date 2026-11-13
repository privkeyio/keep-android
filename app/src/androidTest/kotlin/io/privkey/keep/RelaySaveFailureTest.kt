package io.privkey.keep

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RelaySaveFailureTest {

    private val app: KeepMobileApp get() = ApplicationProvider.getApplicationContext()

    @Test
    fun relayTheCoreRefusesIsReportedNotThrown() = runBlocking(Dispatchers.Main) {
        val mobile = checkNotNull(app.getKeepMobile())
        val key = app.getStorage()?.getActiveShareKey()
        val before = mobile.getRelayConfig(key)

        assertFalse(saveRelaysOrToast(app) { app.initializeWithRelays(listOf("wss://relay.internal")) })
        assertEquals(before, mobile.getRelayConfig(key))

        assertTrue(saveRelaysOrToast(app) { app.initializeWithRelays(before.frostRelays) })
    }
}
