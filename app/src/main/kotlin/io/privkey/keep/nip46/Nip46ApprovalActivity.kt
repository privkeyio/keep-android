package io.privkey.keep.nip46

import android.os.Bundle
import android.util.Log
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
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class Nip46ApprovalActivity : FragmentActivity() {

    private lateinit var biometricHelper: BiometricHelper
    private var storage: AndroidKeystoreStorage? = null
    private var killSwitchStore: KillSwitchStore? = null
    private var requestId: String? = null
    private var approveCompletionCallback: ((Boolean) -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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

        if (killSwitchStore?.isEnabled() == true) {
            respond(false)
            return
        }

        val keystoreStorage = storage
        if (keystoreStorage == null) {
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

            try {
                keystoreStorage.setPendingCipher(authedCipher)
                respond(true)
            } finally {
                // Clear cipher after delay to allow FFI signing to complete.
                // The signing happens asynchronously in the Rust FFI after respond() triggers
                // the callback and handleApprovalRequest returns. We use NonCancellable to ensure
                // cleanup runs even when the activity finishes and cancels the coroutine.
                withContext(NonCancellable) {
                    delay(CIPHER_CLEANUP_DELAY_MS)
                    keystoreStorage.clearPendingCipher()
                }
            }
        }
    }

    companion object {
        private const val TAG = "Nip46ApprovalActivity"
        private const val CIPHER_CLEANUP_DELAY_MS = 5000L
        const val EXTRA_REQUEST_ID = "request_id"
        const val EXTRA_APP_PUBKEY = "app_pubkey"
        const val EXTRA_APP_NAME = "app_name"
        const val EXTRA_METHOD = "method"
        const val EXTRA_EVENT_KIND = "event_kind"
        const val EXTRA_EVENT_CONTENT = "event_content"
        const val EXTRA_IS_CONNECT = "is_connect"
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

    @Deprecated("Use OnBackPressedCallback", ReplaceWith("onBackPressedDispatcher"))
    override fun onBackPressed() {
        respond(false)
        super.onBackPressed()
    }
}
