package io.privkey.keep

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.SecureStorage
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

// The bunker and the relay node connect directly only after a successful read shows the
// proxy off. That depends on a stored proxy config that cannot be read reaching them as an
// error rather than as the default "off".
@RunWith(AndroidJUnit4::class)
class ProxyConfigFaultTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var storage: AndroidKeystoreStorage

    @Before
    fun setup() {
        storage = AndroidKeystoreStorage(context, requireUserAuth = false, keystoreAlias = ALIAS, prefsSuffix = SUFFIX)
    }

    @After
    fun teardown() {
        context.deleteSharedPreferences(MULTI_PREFS)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.aliases().toList().filter { it.startsWith(ALIAS) }.forEach { keyStore.deleteEntry(it) }
    }

    @Test
    fun anUnreadableProxyConfigIsAnErrorNotOff() {
        val faulty = object : SecureStorage by storage {
            override fun loadShareByKey(key: String): ByteArray =
                if (key == PROXY_KEY) throw KeepMobileException.StorageException("injected fault")
                else storage.loadShareByKey(key)
        }
        val mobile = KeepMobile(faulty)
        try {
            val read = runCatching { mobile.getProxyConfig() }
            assertTrue("got ${read.getOrNull()}", read.exceptionOrNull() is KeepMobileException)
        } finally {
            mobile.destroy()
        }
    }

    @Test
    fun aMissingProxyConfigReadsAsOff() {
        val mobile = KeepMobile(storage)
        try {
            assertFalse(mobile.getProxyConfig().enabled)
        } finally {
            mobile.destroy()
        }
    }

    private companion object {
        const val SUFFIX = "_proxy_fault_test"
        const val ALIAS = "keep_frost_share$SUFFIX"
        const val MULTI_PREFS = "keep_multi_share_prefs$SUFFIX"
        const val PROXY_KEY = "__keep_proxy_config_v1"
    }
}
