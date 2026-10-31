package io.privkey.keep.nip46

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.BunkerConfigInfo
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.ShareMetadataInfo
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/**
 * A client list saved before the cap existed can hold more clients than the core now
 * saves, which would refuse every later bunker config save. The oldest clients past the
 * cap are revoked through the core, so the list fits again.
 */
@RunWith(AndroidJUnit4::class)
class BunkerClientCapTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var storage: AndroidKeystoreStorage
    private lateinit var mobile: KeepMobile

    @Before
    fun setup() {
        storage = AndroidKeystoreStorage(context, requireUserAuth = false, keystoreAlias = ALIAS, prefsSuffix = SUFFIX)
        mobile = KeepMobile(storage)
    }

    @After
    fun teardown() {
        mobile.destroy()
        context.deleteSharedPreferences(storage.sharePrefsNameFor(CONFIG_KEY))
        context.deleteSharedPreferences(MULTI_PREFS)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.aliases().toList().filter { it.startsWith(ALIAS) }.forEach { keyStore.deleteEntry(it) }
    }

    private fun storeLegacyList(clients: List<String>) {
        val json = JSONObject().put("enabled", false).put("authorized_clients", JSONArray(clients))
        storage.storeShareByKey(
            CONFIG_KEY,
            json.toString().toByteArray(),
            ShareMetadataInfo("bunker_config", 0u, 0u, 0u, ByteArray(0), false)
        )
    }

    @Test
    fun aListOverTheCapIsCutToTheNewestClients() = runBlocking {
        val kept = (1..BunkerService.MAX_AUTHORIZED_CLIENTS).map { "%064x".format(it) }
        storeLegacyList(OLDEST + kept)
        assertThrows(KeepMobileException::class.java) {
            mobile.saveBunkerConfig(BunkerConfigInfo(true, mobile.getBunkerConfig().authorizedClients))
        }

        BunkerService.revokeClientsOverCap(context, mobile)

        assertEquals(kept, mobile.getBunkerConfig().authorizedClients)
        mobile.saveBunkerConfig(BunkerConfigInfo(true, kept))
        assertEquals(true, mobile.getBunkerConfig().enabled)
    }

    @Test
    fun aListWithinTheCapIsLeftAlone() = runBlocking {
        val clients = OLDEST + (1..BunkerService.MAX_AUTHORIZED_CLIENTS - OLDEST.size).map { "%064x".format(it) }
        storeLegacyList(clients)

        BunkerService.revokeClientsOverCap(context, mobile)

        assertEquals(clients, mobile.getBunkerConfig().authorizedClients)
    }

    private companion object {
        const val SUFFIX = "_bunker_cap_test"
        const val ALIAS = "keep_frost_share$SUFFIX"
        const val MULTI_PREFS = "keep_multi_share_prefs$SUFFIX"
        const val CONFIG_KEY = "__keep_bunker_config_v1"

        // x coordinates of G, 2G and 3G on secp256k1, so the core can parse them to revoke.
        val OLDEST = listOf(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        )
    }
}
