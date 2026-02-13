package io.privkey.keep.nip46

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import androidx.activity.OnBackPressedCallback
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
import io.privkey.keep.nip55.PermissionDuration
import io.privkey.keep.nip55.PermissionStore
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.KillSwitchStore
import io.privkey.keep.ui.theme.KeepAndroidTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class Nip46ApprovalActivity : FragmentActivity() {

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

    private lateinit var biometricHelper: BiometricHelper
    private var storage: AndroidKeystoreStorage? = null
    private var killSwitchStore: KillSwitchStore? = null
    private var permissionStore: PermissionStore? = null
    private var requestId: String? = null
    private var clientPubkey: String? = null
    private var method: String? = null
    private var eventKind: Int? = null
    private var approveCompletionCallback: ((Boolean) -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        val app = application as? KeepMobileApp
        biometricHelper = BiometricHelper(this, app?.getBiometricTimeoutStore())
        storage = app?.getStorage()
        killSwitchStore = app?.getKillSwitchStore()
        permissionStore = app?.getPermissionStore()

        requestId = intent.getStringExtra(EXTRA_REQUEST_ID)
        clientPubkey = intent.getStringExtra(EXTRA_APP_PUBKEY)
        method = intent.getStringExtra(EXTRA_METHOD)
        eventKind = intent.getIntExtra(EXTRA_EVENT_KIND, -1).takeIf { it >= 0 }
        if (requestId == null) {
            if (BuildConfig.DEBUG) Log.e(TAG, "No request ID provided")
            finish()
            return
        }

        val reqId = requestId ?: return
        val pendingApproval = BunkerService.getPendingApproval(reqId)
        if (pendingApproval == null) {
            if (BuildConfig.DEBUG) Log.e(TAG, "No pending approval found for $reqId")
            finish()
            return
        }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                respond(false, null)
            }
        })

        if (killSwitchStore?.isEnabled() == true) {
            respond(false, null)
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

    private fun handleApprove(duration: PermissionDuration, onComplete: (Boolean) -> Unit) {
        approveCompletionCallback = onComplete

        val keystoreStorage = storage
        if (keystoreStorage == null || killSwitchStore?.isEnabled() == true) {
            respond(false, null)
            return
        }

        lifecycleScope.launch {
            val cipher = runCatching { keystoreStorage.getCipherForDecryption() }
                .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to get cipher: ${it::class.simpleName}") }
                .getOrNull()

            if (cipher == null) {
                respond(false, null)
                return@launch
            }

            val authedCipher = runCatching {
                biometricHelper.authenticateWithCrypto(
                    cipher = cipher,
                    title = "Approve NIP-46 Request",
                    subtitle = "Authenticate to sign"
                )
            }.onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Biometric auth failed: ${it::class.simpleName}") }
                .getOrNull()

            if (authedCipher == null) {
                respond(false, null)
                return@launch
            }

            val reqId = requestId ?: run {
                respond(false, null)
                return@launch
            }
            try {
                keystoreStorage.setPendingCipher(reqId, authedCipher) {
                    keystoreStorage.clearPendingCipher(reqId)
                }
                respond(true, duration)
            } catch (e: Exception) {
                keystoreStorage.clearPendingCipher(reqId)
                if (BuildConfig.DEBUG) Log.e(TAG, "Error during approval: ${e::class.simpleName}")
                respond(false, null)
            }
        }
    }

    private suspend fun savePermissionIfRequested(duration: PermissionDuration) {
        val store = permissionStore ?: return
        val pubkey = clientPubkey ?: return
        val methodName = method ?: return

        if (!duration.shouldPersist) return

        withContext(Dispatchers.IO) {
            val callerPackage = "nip46:$pubkey"
            val requestType = mapMethodToNip55RequestType(methodName) ?: return@withContext
            try {
                store.grantPermission(
                    callerPackage = callerPackage,
                    requestType = requestType,
                    eventKind = eventKind,
                    duration = duration
                )
            } catch (t: Throwable) {
                if (BuildConfig.DEBUG) Log.e(TAG, "Failed to persist permission: ${t::class.simpleName}")
            }
        }
    }

    private fun handleReject() {
        respond(false, null)
    }

    private fun respond(approved: Boolean, duration: PermissionDuration?) {
        approveCompletionCallback?.invoke(approved)
        approveCompletionCallback = null
        requestId?.let { BunkerService.respondToApproval(it, approved, clientPubkey) }
        lifecycleScope.launch {
            if (approved && duration != null) {
                savePermissionIfRequested(duration)
            }
            finish()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val newRequestId = intent.getStringExtra(EXTRA_REQUEST_ID)
        val isTimeout = intent.getBooleanExtra(EXTRA_TIMEOUT, false)

        if (isTimeout && newRequestId == requestId) {
            respond(false, null)
            return
        }

        if (newRequestId != null && newRequestId != requestId) {
            requestId?.let { BunkerService.respondToApproval(it, false, clientPubkey) }
            finish()
        }
    }

}
