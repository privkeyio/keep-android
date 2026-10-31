package io.privkey.keep.storage

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.RelayConfigInfo
import io.privkey.keep.uniffi.ShareInfo
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/**
 * The relay settings reset as the app drives it: through this device's storage, against a
 * record whose ciphertext no longer decrypts.
 */
@RunWith(AndroidJUnit4::class)
class RelayConfigResetTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var storage: AndroidKeystoreStorage
    private lateinit var mobile: KeepMobile
    private val created = mutableSetOf<String>()

    @Before
    fun setup() {
        storage = AndroidKeystoreStorage(context, requireUserAuth = false, keystoreAlias = ALIAS, prefsSuffix = SUFFIX)
        mobile = KeepMobile(storage)
    }

    @After
    fun teardown() {
        created.forEach { group ->
            runCatching { mobile.deleteShareByKey(group) }
            context.deleteSharedPreferences(storage.sharePrefsNameFor(group))
            context.deleteSharedPreferences(storage.sharePrefsNameFor(relayConfigKey(group)))
        }
        context.deleteSharedPreferences(MULTI_PREFS)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.aliases().toList().filter { it.startsWith(ALIAS) }.forEach { keyStore.deleteEntry(it) }
    }

    private fun importShare(): ShareInfo {
        val export = mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "relay-reset-test", PASSPHRASE).shares.first().exportData
        val requestId = "relay-reset-test-${System.nanoTime()}"
        storage.setPendingCipher(requestId, storage.getCipherForEncryption())
        storage.setRequestIdContext(requestId)
        try {
            return mobile.importShare(export, PASSPHRASE, "relay-reset-test").also { created += it.groupPubkey }
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
        }
    }

    private fun corruptRelayConfig(group: String) {
        val prefsName = storage.sharePrefsNameFor(relayConfigKey(group))
        val data = KeystoreEncryptedPrefs.create(context, prefsName).getString(SHARE_DATA, null)!!
        corruptExistingValue(context, prefsName, SHARE_DATA) { it.putString(SHARE_DATA, data) }
    }

    @Test
    fun anUnreadableRelayConfigResetsToTheDefaults() {
        val share = importShare()
        val group = share.groupPubkey
        val defaults = mobile.getRelayConfig(group)
        mobile.saveRelayConfig(group, RelayConfigInfo(listOf(CUSTOM_RELAY), emptyList(), emptyList()))
        assertNotEquals(defaults, mobile.getRelayConfig(group))
        corruptRelayConfig(group)

        assertThrows(KeepMobileException::class.java) { mobile.getRelayConfig(group) }
        mobile.resetUnreadableRelayConfig(group)

        assertEquals(defaults, mobile.getRelayConfig(group))
        val stored = JSONObject(String(storage.loadShareByKey(relayConfigKey(group)), Charsets.UTF_8))
        val policies = stored.getJSONArray("share_peer_policies")
        val blocked = (0 until policies.length()).map { policies.getJSONObject(it) }
        assertEquals(
            (1..share.totalShares.toInt()).filter { it != share.shareIndex.toInt() },
            blocked.map { it.getInt("share_index") }
        )
        blocked.forEach {
            assertFalse(it.getBoolean("allow_send"))
            assertFalse(it.getBoolean("allow_receive"))
        }
    }

    @Test
    fun aReadableRelayConfigIsNotReset() {
        val group = importShare().groupPubkey
        mobile.saveRelayConfig(group, RelayConfigInfo(listOf(CUSTOM_RELAY), emptyList(), emptyList()))
        val saved = mobile.getRelayConfig(group)

        assertThrows(KeepMobileException.InvalidInput::class.java) { mobile.resetUnreadableRelayConfig(group) }
        assertEquals(saved, mobile.getRelayConfig(group))
    }

    private fun relayConfigKey(group: String) = "__keep_relay_config_$group"

    private companion object {
        const val SUFFIX = "_relay_reset_test"
        const val ALIAS = "keep_frost_share$SUFFIX"
        const val MULTI_PREFS = "keep_multi_share_prefs$SUFFIX"
        const val SHARE_DATA = "share_data"
        const val PASSPHRASE = "relay-reset-test-passphrase"
        const val CUSTOM_RELAY = "wss://relay.example.com"
    }
}
