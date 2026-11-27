package io.privkey.keep.nip46

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.SystemClock
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
import io.privkey.keep.uniffi.BunkerStatus
import io.privkey.keep.uniffi.NostrConnectInfo
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.lang.ref.WeakReference
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference

/**
 * Approves a `nostrconnect://` request, from a link another app opened or a code scanned on
 * the bunker screen. The core parses, checks and answers it; this shows what it asks for and
 * takes the user's approval. The URI carries the client's secret, so it is never logged, and a
 * scanned one is handed over in-process ([intent]) rather than as Intent data.
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
    private var account: String? = null
    private var approving = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.setHideOverlayWindows(true)
        // No timeout store: pairing always prompts, and its prompt opens no window for other flows.
        biometricHelper = BiometricHelper(this, null)

        val requestUri = requestUri(intent)
        val keepMobile = keepApp?.getKeepMobile()
        if (requestUri == null || keepMobile == null) {
            // A scanned request's token is taken on the first create, and the URI is never saved
            // since it carries the client's secret, so a recreated screen just closes: its accept,
            // if one started, reports its own result, unless the process died, when the core
            // rolls the accept back on its next start.
            if (savedInstanceState != null) finish() else finishWith(getString(R.string.connections_nostrconnect_invalid))
            return
        }
        if (keepApp?.isSigningKilled() == true) {
            finishWith(getString(R.string.kill_switch_active_toast))
            return
        }
        if (keepApp?.getPinStore()?.requiresAuthentication() == true) {
            finishWith(getString(R.string.connections_nostrconnect_error_locked))
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
            if (BunkerService.isAcceptingNostrconnect(parsed.clientPubkey)) {
                finish()
                return@launch
            }
            uri = requestUri
            info = parsed
            account = activeAccount()
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
        if (approving) return
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
        if (app.getPinStore()?.requiresAuthentication() == true) {
            onComplete(false)
            finishWith(getString(R.string.connections_nostrconnect_error_locked))
            return
        }
        // The request was shown for this account; a switch since then must not pair it with another.
        if (account == null || activeAccount() != account) {
            onComplete(false)
            finishWith(getString(R.string.connections_nostrconnect_error_account_changed))
            return
        }
        val status = biometricHelper.checkBiometricStatus()
        if (status != BiometricHelper.BiometricStatus.AVAILABLE) {
            Toast.makeText(this, BiometricHelper.getBiometricNotReadyMessage(this, status), Toast.LENGTH_LONG).show()
            onComplete(false)
            return
        }
        val name = nostrconnectDisplayName(request.name) ?: getString(R.string.connections_nostrconnect_unknown_app)

        approving = true
        lifecycleScope.launch {
            // Adding a signer client is authorized now, never inside the biometric timeout window.
            val authed = biometricHelper.authenticate(
                title = getString(R.string.connections_nostrconnect_auth_title),
                subtitle = getString(R.string.connections_nostrconnect_auth_subtitle, name),
                forcePrompt = true
            )
            if (!authed) {
                approving = false
                onComplete(false)
                return@launch
            }
            // The prompt can stay up for a while, so what was checked before it is checked again.
            val refusal = when {
                app.isSigningKilled() -> R.string.kill_switch_active_toast
                app.getPinStore()?.requiresAuthentication() == true -> R.string.connections_nostrconnect_error_locked
                activeAccount() != account -> R.string.connections_nostrconnect_error_account_changed
                else -> null
            }
            if (refusal != null) {
                approving = false
                onComplete(false)
                finishWith(getString(refusal))
                return@launch
            }
            // The accept runs detached in the service, which shows its result, so leaving this
            // screen cancels only the wait here. Only the outcome comes back, and only while the
            // screen is still up.
            val screen = WeakReference(this@NostrConnectActivity)
            val connected = try {
                BunkerService.acceptNostrconnect(applicationContext, requestUri, request, approvedPerms) == NostrconnectOutcome.CONNECTED
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                false
            }
            screen.get()?.takeUnless { it.isDestroyed }?.let {
                it.approving = false
                onComplete(connected)
                it.finish()
            }
        }
    }

    private fun activeAccount(): String? = runCatching { keepApp?.getStorage()?.getActiveShareKey() }.getOrNull()

    private fun finishWith(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        finish()
    }

    companion object {
        private const val TAG = "NostrConnectActivity"
        const val SCHEME = "nostrconnect"
        private const val EXTRA_HANDOFF = "io.privkey.keep.nip46.NOSTRCONNECT_HANDOFF"

        private const val HANDOFF_TTL_MS = 60_000L

        private class Handoff(val token: String, val uri: String, val at: Long)

        // The scanned request by one-shot token: the URI carries the client's secret, which Intent
        // data would expose to system logging, so only the token travels in the Intent. One slot,
        // which the next scan replaces, and dropped unused once stale on the next read, so a screen
        // that never opened does not keep the secret for long.
        private val handedOff = AtomicReference<Handoff?>(null)

        /** Opens the approval for a scanned [uri], handed over in-process and taken once. */
        fun intent(context: Context, uri: String): Intent {
            val token = UUID.randomUUID().toString()
            handedOff.set(Handoff(token, uri, SystemClock.elapsedRealtime()))
            return Intent(context, NostrConnectActivity::class.java).putExtra(EXTRA_HANDOFF, token)
        }

        // A scanned request by its token, or a link another app opened. An unknown or stale token
        // gets null, never the Intent data.
        private fun requestUri(intent: Intent?): String? {
            intent ?: return null
            intent.getStringExtra(EXTRA_HANDOFF)?.let { token ->
                val handoff = handedOff.get() ?: return null
                val stale = SystemClock.elapsedRealtime() - handoff.at > HANDOFF_TTL_MS
                if (stale) {
                    handedOff.compareAndSet(handoff, null)
                    return null
                }
                if (handoff.token != token || !handedOff.compareAndSet(handoff, null)) return null
                return handoff.uri.takeIf { Uri.parse(it).scheme == SCHEME }
            }
            return intent.data?.takeIf { it.scheme == SCHEME }?.toString()
        }
    }
}
