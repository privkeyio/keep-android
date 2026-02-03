package io.privkey.keep.nip46

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import io.privkey.keep.BiometricHelper
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.KillSwitchStore
import io.privkey.keep.ui.theme.KeepAndroidTheme
import kotlinx.coroutines.launch

class Nip46ApprovalActivity : FragmentActivity() {

    private lateinit var biometricHelper: BiometricHelper
    private var storage: AndroidKeystoreStorage? = null
    private var killSwitchStore: KillSwitchStore? = null
    private var requestId: String? = null
    private var approveCompletionCallback: ((Boolean) -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        biometricHelper = BiometricHelper(this)
        val app = application as? KeepMobileApp
        storage = app?.getStorage()
        killSwitchStore = app?.getKillSwitchStore()

        requestId = intent.getStringExtra(EXTRA_REQUEST_ID)
        if (requestId == null) {
            Log.e(TAG, "No request ID provided")
            finish()
            return
        }

        val pendingApproval = BunkerService.getPendingApproval(requestId!!)
        if (pendingApproval == null) {
            Log.e(TAG, "No pending approval found for $requestId")
            finish()
            return
        }

        if (killSwitchStore?.isEnabled() == true) {
            respond(false)
            return
        }

        val request = pendingApproval.request
        val isConnect = pendingApproval.isConnectRequest

        setContent {
            KeepAndroidTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    Nip46ApprovalScreen(
                        appPubkey = request.appPubkey,
                        appName = request.appName,
                        method = request.method,
                        eventKind = request.eventKind?.toInt(),
                        eventContent = request.eventContent,
                        isConnectRequest = isConnect,
                        onApprove = ::handleApprove,
                        onReject = ::handleReject
                    )
                }
            }
        }
    }

    private fun handleApprove(onComplete: (Boolean) -> Unit) {
        approveCompletionCallback = onComplete

        val keystoreStorage = storage
        if (keystoreStorage == null || killSwitchStore?.isEnabled() == true) {
            respond(false)
            return
        }

        lifecycleScope.launch {
            val cipher = runCatching { keystoreStorage.getCipherForDecryption() }
                .onFailure { Log.e(TAG, "Failed to get cipher: ${it::class.simpleName}") }
                .getOrNull()

            if (cipher == null) {
                respond(false)
                return@launch
            }

            val authedCipher = runCatching {
                biometricHelper.authenticateWithCrypto(
                    cipher = cipher,
                    title = "Approve NIP-46 Request",
                    subtitle = "Authenticate to sign"
                )
            }.onFailure { Log.e(TAG, "Biometric auth failed: ${it::class.simpleName}") }
                .getOrNull()

            if (authedCipher == null) {
                respond(false)
                return@launch
            }

            val reqId = requestId!!
            keystoreStorage.setPendingCipher(reqId, authedCipher) {
                keystoreStorage.clearPendingCipher(reqId)
            }
            respond(true)
        }
    }

    companion object {
        private const val TAG = "Nip46ApprovalActivity"
        const val EXTRA_REQUEST_ID = "request_id"
        const val EXTRA_APP_PUBKEY = "app_pubkey"
        const val EXTRA_APP_NAME = "app_name"
        const val EXTRA_METHOD = "method"
        const val EXTRA_EVENT_KIND = "event_kind"
        const val EXTRA_EVENT_CONTENT = "event_content"
        const val EXTRA_IS_CONNECT = "is_connect"
        const val EXTRA_TIMEOUT = "timeout"
    }

    private fun handleReject() {
        respond(false)
    }

    private fun respond(approved: Boolean) {
        approveCompletionCallback?.invoke(approved)
        approveCompletionCallback = null
        requestId?.let { BunkerService.respondToApproval(it, approved) }
        finish()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val newRequestId = intent.getStringExtra(EXTRA_REQUEST_ID)
        val isTimeout = intent.getBooleanExtra(EXTRA_TIMEOUT, false)

        if (isTimeout && newRequestId == requestId) {
            respond(false)
            return
        }

        if (newRequestId != null && newRequestId != requestId) {
            requestId?.let { BunkerService.respondToApproval(it, false) }
            finish()
        }
    }

    @Deprecated("Use OnBackPressedCallback", ReplaceWith("onBackPressedDispatcher"))
    override fun onBackPressed() {
        respond(false)
        super.onBackPressed()
    }
}
