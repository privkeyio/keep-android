package io.privkey.keep.nip55

import android.content.Intent
import android.os.Binder
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
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.Nip55Response
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class Nip55Activity : FragmentActivity() {
    private lateinit var biometricHelper: BiometricHelper
    private var handler: Nip55Handler? = null
    private var permissionStore: PermissionStore? = null
    private var request: Nip55Request? = null
    private var requestId: String? = null
    private var callerPackage: String? = null
    private var callerVerified: Boolean = false

    companion object {
        private const val TAG = "Nip55Activity"
        private const val GENERIC_ERROR_MESSAGE = "An error occurred"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        biometricHelper = BiometricHelper(this)
        val app = application as? KeepMobileApp
        handler = app?.getNip55Handler()
        permissionStore = app?.getPermissionStore()
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        identifyCaller()
        requestId = intent.getStringExtra("id")
        parseAndSetRequest(intent)
        if (request != null) setupContent()
    }

    private fun identifyCaller() {
        callingActivity?.let {
            callerPackage = it.packageName
            callerVerified = true
            return
        }

        val callingUid = Binder.getCallingUid()
        if (callingUid == android.os.Process.myUid()) {
            callerPackage = null
            callerVerified = false
            return
        }

        val packages = packageManager.getPackagesForUid(callingUid)
        callerVerified = packages?.size == 1
        callerPackage = if (callerVerified) packages?.firstOrNull() else null
    }

    private fun setupContent() {
        val currentRequest = request ?: return
        val currentCallerPackage = callerPackage
        val currentCallerVerified = callerVerified

        setContent {
            KeepAndroidTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    ApprovalScreen(
                        request = currentRequest,
                        callerPackage = currentCallerPackage,
                        callerVerified = currentCallerVerified,
                        onApprove = ::handleApprove,
                        onReject = ::handleReject
                    )
                }
            }
        }
    }

    private fun parseAndSetRequest(intent: Intent) {
        val uri = intent.data?.toString() ?: return finishWithError("Invalid request")

        val parsed = runCatching { handler?.parseIntentUri(uri) }.getOrNull()
            ?: return finishWithError("Invalid request")

        request = parsed
        if (requestId.isNullOrBlank()) {
            requestId = parsed.id
        }
    }

    private fun handleApprove(duration: PermissionDuration) {
        val req = request ?: return
        val h = handler ?: return finishWithError("Handler not initialized")
        val callerId = callerPackage ?: "unknown"
        val store = permissionStore
        val eventKind = if (req.requestType == Nip55RequestType.SIGN_EVENT) {
            parseEventKind(req.content)
        } else null

        lifecycleScope.launch {
            val needsBiometric = req.requestType != Nip55RequestType.GET_PUBLIC_KEY

            if (needsBiometric) {
                val authenticated = biometricHelper.authenticate(
                    title = "Approve Request",
                    subtitle = req.requestType.displayName()
                )
                if (!authenticated) {
                    finishWithError("Authentication failed")
                    return@launch
                }
            }

            if (store != null && callerId != "unknown") {
                store.grantPermission(callerId, req.requestType, eventKind, duration)
            }

            val result = withContext(Dispatchers.Default) {
                runCatching { h.handleRequest(req, callerId) }
            }

            result.fold(
                onSuccess = { response ->
                    store?.logOperation(callerId, req.requestType, eventKind, "allow", wasAutomatic = false)
                    finishWithResult(response)
                },
                onFailure = { e ->
                    val errorMsg = when (e) {
                        is KeepMobileException.RateLimited -> "rate_limited"
                        is KeepMobileException.NotInitialized -> "not_initialized"
                        is KeepMobileException.PubkeyMismatch -> "pubkey_mismatch"
                        is KeepMobileException.InvalidTimestamp -> "invalid_timestamp"
                        else -> "request_failed"
                    }
                    Log.e(TAG, "Request failed: ${e::class.simpleName}")
                    finishWithError(errorMsg)
                }
            )
        }
    }

    private fun handleReject(duration: PermissionDuration) {
        val req = request
        val callerId = callerPackage ?: "unknown"
        val store = permissionStore
        val eventKind = if (req?.requestType == Nip55RequestType.SIGN_EVENT) {
            parseEventKind(req.content)
        } else null

        lifecycleScope.launch {
            if (store != null && callerId != "unknown" && req != null) {
                store.denyPermission(callerId, req.requestType, eventKind, duration)
                store.logOperation(callerId, req.requestType, eventKind, "deny", wasAutomatic = false)
            }
            finishWithError("User rejected")
        }
    }

    private fun finishWithResult(response: Nip55Response) {
        val req = request
        val resultIntent = Intent().apply {
            putExtra("result", response.result)
            putExtra("package", packageName)
            response.event?.let { putExtra("event", it) }
            requestId?.let { putExtra("id", it) }
            if (req?.requestType == Nip55RequestType.GET_PUBLIC_KEY) {
                putExtra("pubkey", response.result)
            }
        }
        setResult(RESULT_OK, resultIntent)
        finish()
    }

    private fun finishWithError(error: String) {
        Log.e(TAG, "NIP-55 request failed: $error${requestId?.let { " (requestId=$it)" } ?: ""}")
        val resultIntent = Intent().apply {
            putExtra("error", GENERIC_ERROR_MESSAGE)
        }
        setResult(RESULT_CANCELED, resultIntent)
        finish()
    }
}
