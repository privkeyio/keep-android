package io.privkey.keep.nip46

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import io.privkey.keep.BiometricHelper
import io.privkey.keep.BuildConfig
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.R
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.BunkerHandler
import io.privkey.keep.uniffi.BunkerStatus
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.NostrConnectInfo
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.lang.ref.WeakReference
import java.util.concurrent.ConcurrentHashMap

/**
 * Approves a `nostrconnect://` request, from a link another app opened or a code scanned on
 * the bunker screen. The core parses, checks and answers it; this shows what it asks for and
 * takes the user's approval. The URI carries the client's secret, so it is never logged.
 *
 * It is singleTop and does not handle onNewIntent: a request that arrives while one is shown is
 * dropped, so the user answers the one in front of them and the app that sent the other can show
 * its code again. It handles configuration changes itself, so a rotation does not recreate it,
 * and a screen for a client whose accept is in flight closes rather than offer it again.
 */
class NostrConnectActivity : FragmentActivity() {

    private val keepApp: KeepMobileApp? get() = application as? KeepMobileApp
    private lateinit var biometricHelper: BiometricHelper
    private var uri: String? = null
    private var info: NostrConnectInfo? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.setHideOverlayWindows(true)
        biometricHelper = BiometricHelper(this, keepApp?.getBiometricTimeoutStore())

        val requestUri = intent?.data?.takeIf { it.scheme == SCHEME }?.toString()
        val keepMobile = keepApp?.getKeepMobile()
        if (requestUri == null || keepMobile == null) {
            finishWith(getString(R.string.connections_nostrconnect_invalid))
            return
        }
        if (keepApp?.isSigningKilled() == true) {
            finishWith(getString(R.string.kill_switch_active_toast))
            return
        }
        if (BunkerService.status.value != BunkerStatus.RUNNING) {
            finishWith(getString(R.string.connections_nostrconnect_error_not_running))
            return
        }

        lifecycleScope.launch {
            val parsed = withContext(Dispatchers.IO) {
                runCatching { BunkerHandler(keepMobile).use { it.parseNostrconnect(requestUri) } }
                    .onFailure { if (BuildConfig.DEBUG) Log.w(TAG, "Unusable nostrconnect request: ${it::class.simpleName}") }
                    .getOrNull()
            }
            if (parsed == null) {
                finishWith(getString(R.string.connections_nostrconnect_invalid))
                return@launch
            }
            // Its accept is already running, and reports its own result.
            if (parsed.clientPubkey.lowercase() in accepting) {
                finish()
                return@launch
            }
            uri = requestUri
            info = parsed
            setContent {
                KeepAndroidTheme {
                    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                        NostrConnectApprovalScreen(info = parsed, onApprove = ::handleApprove, onReject = ::finish)
                    }
                }
            }
        }
    }

    private fun handleApprove(approvedPerms: String, onComplete: (Boolean) -> Unit) {
        val requestUri = uri
        val request = info
        val app = keepApp
        if (requestUri == null || request == null || app == null) {
            onComplete(false)
            finish()
            return
        }
        if (app.isSigningKilled()) {
            onComplete(false)
            finishWith(getString(R.string.kill_switch_active_toast))
            return
        }
        val status = biometricHelper.checkBiometricStatus()
        if (status != BiometricHelper.BiometricStatus.AVAILABLE) {
            Toast.makeText(this, BiometricHelper.getBiometricNotReadyMessage(this, status), Toast.LENGTH_LONG).show()
            onComplete(false)
            return
        }
        val pk = request.clientPubkey.lowercase()
        val name = nostrconnectDisplayName(request.name) ?: getString(R.string.connections_nostrconnect_unknown_app)

        lifecycleScope.launch {
            // Adding a signer client is authorized now, never inside the biometric timeout window.
            val authed = biometricHelper.authenticate(
                title = getString(R.string.connections_nostrconnect_auth_title),
                subtitle = getString(R.string.connections_nostrconnect_auth_subtitle, name),
                forcePrompt = true
            )
            if (!authed) {
                onComplete(false)
                return@launch
            }
            // Another screen's accept for this client got there first and reports its own result.
            if (!accepting.add(pk)) {
                onComplete(false)
                finishWith(getString(R.string.connections_nostrconnect_already_connecting))
                return@launch
            }
            // Once asked, the core may accept, so the accept and the admission that must follow
            // it run on the application's scope, which leaving this screen does not cancel. Only
            // the result comes back here, and only while the screen is still up.
            val appContext = applicationContext
            val screen = WeakReference(this@NostrConnectActivity)
            app.launchDetached {
                val (connected, message) = try {
                    if (BunkerService.acceptNostrconnect(appContext, requestUri, request, approvedPerms)) {
                        true to appContext.getString(R.string.connections_nostrconnect_connected, name)
                    } else {
                        false to appContext.getString(R.string.connections_nostrconnect_error_revoked)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    if (BuildConfig.DEBUG) Log.w(TAG, "nostrconnect accept failed: ${e::class.simpleName}")
                    false to appContext.getString(acceptErrorMessage(e))
                } finally {
                    accepting.remove(pk)
                }
                withContext(Dispatchers.Main) {
                    Toast.makeText(appContext, message, Toast.LENGTH_LONG).show()
                    screen.get()?.takeUnless { it.isDestroyed }?.let {
                        onComplete(connected)
                        it.finish()
                    }
                }
            }
        }
    }

    private fun finishWith(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        finish()
    }

    companion object {
        private const val TAG = "NostrConnectActivity"
        const val SCHEME = "nostrconnect"

        // Clients whose accept is in flight, so another screen for one neither offers it again
        // nor races the first accept.
        private val accepting: MutableSet<String> = ConcurrentHashMap.newKeySet()

        fun intent(context: Context, uri: String): Intent =
            Intent(context, NostrConnectActivity::class.java).setData(Uri.parse(uri))

        @StringRes
        private fun acceptErrorMessage(e: Exception): Int = when (e) {
            is KeepMobileException.BunkerNotRunning -> R.string.connections_nostrconnect_error_not_running
            is KeepMobileException.TooManyAuthorizedClients -> R.string.nip46_client_limit_toast
            is KeepMobileException.PolicyViolation -> R.string.kill_switch_active_toast
            is KeepMobileException.Timeout -> R.string.connections_nostrconnect_error_timeout
            is KeepMobileException.NetworkException -> R.string.connections_nostrconnect_error_network
            is KeepMobileException.CertificatePinMismatch -> R.string.certificate_pin_mismatch_error
            // The request already parsed, so an input error here is not a bad request. The core
            // refuses a client it already lists with one (keep-mobile nip46.rs
            // refuse_to_register), told apart only by its message until the core reports it as
            // ClientAlreadyConnected (privkeyio/keep follow-up).
            is KeepMobileException.InvalidInput ->
                if (e.msg.contains("already connected")) R.string.connections_nostrconnect_error_already_connected
                else R.string.connections_nostrconnect_error_failed
            else -> R.string.connections_nostrconnect_error_failed
        }
    }
}
