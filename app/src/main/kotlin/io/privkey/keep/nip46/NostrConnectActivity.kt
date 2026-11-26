package io.privkey.keep.nip46

import android.content.Context
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
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
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.NostrConnectInfo
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Opens a `nostrconnect://` link: shows what the core read from it and, once the user approves
 * and authenticates, hands the link to the running bunker. The core parses it, checks and pins
 * the client's relays, grants only what it asked for, lists the client and sends the reply.
 */
class NostrConnectActivity : FragmentActivity() {

    private val keepApp: KeepMobileApp? get() = application as? KeepMobileApp
    private lateinit var biometric: BiometricHelper
    private var accepting = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.setHideOverlayWindows(true)
        // No timeout store: pairing always prompts, and its prompt opens no window for other flows.
        biometric = BiometricHelper(this, null)

        val uri = intent?.dataString
        val mobile = keepApp?.getKeepMobile()
        if (uri == null || mobile == null) {
            finish()
            return
        }
        if (keepApp?.isSigningKilled() == true) {
            finishWith(getString(R.string.kill_switch_active_toast))
            return
        }
        if (keepApp?.getPinStore()?.requiresAuthentication() == true) {
            finishWith(getString(R.string.connections_nostrconnect_locked))
            return
        }
        if (!BunkerService.isServing()) {
            finishWith(getString(R.string.connections_nostrconnect_bunker_stopped))
            return
        }

        lifecycleScope.launch {
            val info = withContext(Dispatchers.IO) {
                runCatching { BunkerHandler(mobile).use { it.parseNostrconnect(uri) } }
                    .onFailure { if (BuildConfig.DEBUG) Log.w(TAG, "Unreadable nostrconnect link: ${it::class.simpleName}") }
                    .getOrNull()
            }
            if (info == null) {
                finishWith(getString(R.string.connections_nostrconnect_invalid))
                return@launch
            }
            setContent {
                KeepAndroidTheme {
                    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                        NostrConnectApprovalScreen(
                            info = info,
                            onApprove = { onComplete -> approve(uri, info, onComplete) },
                            onReject = ::finish,
                        )
                    }
                }
            }
        }
    }

    private fun approve(uri: String, info: NostrConnectInfo, onComplete: (Boolean) -> Unit) {
        if (accepting) return
        if (keepApp?.isSigningKilled() == true) {
            finishWith(getString(R.string.kill_switch_active_toast))
            return
        }
        if (keepApp?.getPinStore()?.requiresAuthentication() == true) {
            finishWith(getString(R.string.connections_nostrconnect_locked))
            return
        }
        val status = biometric.checkBiometricStatus()
        if (status != BiometricHelper.BiometricStatus.AVAILABLE) {
            finishWith(BiometricHelper.getBiometricNotReadyMessage(this, status))
            return
        }
        accepting = true
        lifecycleScope.launch {
            val name = info.name?.let(::sanitizeDisplayName) ?: getString(R.string.connections_nostrconnect_unnamed)
            val authenticated = runCatching {
                biometric.authenticate(
                    title = getString(R.string.connections_nostrconnect_auth_title),
                    subtitle = getString(R.string.connections_nostrconnect_auth_subtitle, name),
                    forcePrompt = true,
                )
            }.getOrDefault(false)
            if (!authenticated) {
                accepting = false
                onComplete(false)
                return@launch
            }
            val failure = withContext(Dispatchers.IO) {
                try {
                    BunkerService.acceptNostrconnect(this@NostrConnectActivity, uri, info)
                    null
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    e
                }
            }
            if (failure != null && BuildConfig.DEBUG) Log.w(TAG, "nostrconnect accept failed: ${failure::class.simpleName}")
            onComplete(failure == null)
            finishWith(failure?.let { errorText(this@NostrConnectActivity, it) } ?: getString(R.string.connections_nostrconnect_connected))
        }
    }

    private fun finishWith(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        finish()
    }

    companion object {
        private const val TAG = "NostrConnectActivity"

        fun errorText(context: Context, e: Throwable): String = when (e) {
            is KeepMobileException.BunkerNotRunning -> context.getString(R.string.connections_nostrconnect_bunker_stopped)
            is KeepMobileException.TooManyAuthorizedClients -> context.getString(R.string.nip46_client_limit_toast)
            is KeepMobileException.PolicyViolation -> context.getString(R.string.kill_switch_active_toast)
            is KeepMobileException.CertificatePinMismatch -> context.getString(R.string.connections_nostrconnect_pin_mismatch)
            is KeepMobileException.NetworkException -> context.getString(R.string.connections_nostrconnect_network, e.msg)
            is KeepMobileException.InvalidInput -> e.msg
            else -> context.getString(R.string.connections_nostrconnect_failed)
        }
    }
}
