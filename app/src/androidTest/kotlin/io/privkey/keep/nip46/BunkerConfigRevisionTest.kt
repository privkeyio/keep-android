package io.privkey.keep.nip46

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.BunkerConfigInfo
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.KeepMobileException
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/**
 * The core can list a client outside the app's config lock, as a nostrconnect accept does,
 * so a save built on an older read must not drop it. The reset on an account switch still
 * drops every client.
 */
@RunWith(AndroidJUnit4::class)
class BunkerConfigRevisionTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var storage: AndroidKeystoreStorage
    private lateinit var mobile: KeepMobile

    @Before
    fun setup() {
        storage = AndroidKeystoreStorage(context, requireUserAuth = false, keystoreAlias = ALIAS, prefsSuffix = SUFFIX)
        mobile = KeepMobile(storage)
        mobile.saveBunkerConfig(BunkerConfigInfo(false, listOf(FIRST)))
    }

    @After
    fun teardown() {
        mobile.destroy()
        context.deleteSharedPreferences(storage.sharePrefsNameFor(CONFIG_KEY))
        context.deleteSharedPreferences(MULTI_PREFS)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.aliases().toList().filter { it.startsWith(ALIAS) }.forEach { keyStore.deleteEntry(it) }
    }

    @Test
    fun aSaveFromAnOlderReadIsRefused() {
        val read = mobile.getBunkerConfig()
        mobile.saveBunkerConfig(BunkerConfigInfo(false, listOf(FIRST, LISTED_SINCE)))
        assertThrows(KeepMobileException.InvalidInput::class.java) {
            mobile.saveBunkerConfig(read.copy(enabled = true))
        }
        assertEquals(listOf(FIRST, LISTED_SINCE), mobile.getBunkerConfig().authorizedClients)
    }

    @Test
    fun aToggleRacingAListingKeepsTheNewClient() = runBlocking {
        var runs = 0
        val saved = BunkerConfigStore.update(mobile) { current ->
            if (runs++ == 0) mobile.saveBunkerConfig(BunkerConfigInfo(false, listOf(FIRST, LISTED_SINCE)))
            current.copy(enabled = true)
        }
        assertEquals("the toggle ran again on a fresh read", 2, runs)
        assertEquals(listOf(FIRST, LISTED_SINCE), saved.authorizedClients)
        val stored = mobile.getBunkerConfig()
        assertEquals(true, stored.enabled)
        assertEquals(listOf(FIRST, LISTED_SINCE), stored.authorizedClients)
    }

    @Test
    fun aListThatKeepsChangingGivesUp() = runBlocking {
        var runs = 0
        assertThrows(KeepMobileException.InvalidInput::class.java) {
            runBlocking {
                BunkerConfigStore.update(mobile) { current ->
                    runs++
                    mobile.saveBunkerConfig(BunkerConfigInfo(false, listOf(FIRST, "%064x".format(runs + 10))))
                    current.copy(enabled = true)
                }
            }
        }
        assertEquals(3, runs)
        assertEquals(false, mobile.getBunkerConfig().enabled)
    }

    @Test
    fun theResetDropsAClientListedAfterItsRead() = runBlocking {
        BunkerConfigStore.update(mobile) {
            mobile.saveBunkerConfig(BunkerConfigInfo(true, listOf(FIRST, LISTED_SINCE)))
            BunkerConfigInfo(false, emptyList())
        }
        assertEquals(emptyList<String>(), mobile.getBunkerConfig().authorizedClients)
    }

    private companion object {
        const val SUFFIX = "_bunker_revision_test"
        const val ALIAS = "keep_frost_share$SUFFIX"
        const val MULTI_PREFS = "keep_multi_share_prefs$SUFFIX"
        const val CONFIG_KEY = "__keep_bunker_config_v1"
        val FIRST = "%064x".format(1)
        val LISTED_SINCE = "%064x".format(2)
    }
}
