package io.privkey.keep.nip46

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.BunkerApprovalRequest
import io.privkey.keep.uniffi.BunkerApprovalResult
import io.privkey.keep.uniffi.BunkerCallbacks
import io.privkey.keep.uniffi.BunkerHandler
import io.privkey.keep.uniffi.BunkerLogEvent
import io.privkey.keep.uniffi.BunkerRememberDuration
import io.privkey.keep.uniffi.ConnectAuthorization
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.KeepMobileException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.ServerSocket
import java.security.KeyStore
import kotlin.concurrent.thread

// With a proxy configured the bunker must reach its relays through it. The start path
// once looked the core method up by name, which never matched the mangled JVM name of a
// method taking a UShort, so every proxied start failed before reaching the core.
@RunWith(AndroidJUnit4::class)
class BunkerProxyStartTest {

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
        context.deleteSharedPreferences(MULTI_PREFS)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.aliases().toList().filter { it.startsWith(ALIAS) }.forEach { keyStore.deleteEntry(it) }
    }

    @Test
    fun aProxiedStartConnectsToTheRelayThroughTheProxy() {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { proxy ->
            proxy.soTimeout = 30_000
            val handler = BunkerHandler(mobile)
            var outcome: Result<Unit>? = null
            val start = thread {
                outcome = runCatching { BunkerService.startBunkerThroughProxy(handler, listOf(RELAY), NoCallbacks, proxy.localPort.toUShort()) }
            }
            try {
                val greeting = proxy.accept().use { it.getInputStream().read() }
                assertEquals("a SOCKS5 greeting from the core", SOCKS5, greeting)
            } finally {
                handler.stopBunker()
                start.join(60_000)
                handler.destroy()
            }
            // The proxy closed without answering, so the core's error must reach the
            // service, which retries or fails closed on it rather than reading a bare false.
            assertTrue(
                "the core's error is thrown, got $outcome",
                outcome?.exceptionOrNull() is KeepMobileException
            )
        }
    }

    private object NoCallbacks : BunkerCallbacks {
        override fun onLog(event: BunkerLogEvent) = Unit
        override fun requestApproval(request: BunkerApprovalRequest) =
            BunkerApprovalResult(false, BunkerRememberDuration.JUST_THIS_TIME)
        override fun onConnect(pubkey: String, name: String, authorization: ConnectAuthorization) = Unit
    }

    private companion object {
        const val SUFFIX = "_bunker_proxy_test"
        const val ALIAS = "keep_frost_share$SUFFIX"
        const val MULTI_PREFS = "keep_multi_share_prefs$SUFFIX"
        const val RELAY = "wss://relay.example.com"
        const val SOCKS5 = 5
    }
}
