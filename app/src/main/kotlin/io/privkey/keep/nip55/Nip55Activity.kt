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
    private var batchRequests: List<Nip55Request>? = null
    private var requestId: String? = null
    private var callerPackage: String? = null
    private var callerVerified: Boolean = false
    private var currentUser: String? = null
    private var permissions: String? = null

    companion object {
        private const val TAG = "Nip55Activity"
        private const val GENERIC_ERROR_MESSAGE = "An error occurred"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        biometricHelper = BiometricHelper(this)
        handler = (application as? KeepMobileApp)?.getNip55Handler()
        permissionStore = (application as? KeepMobileApp)?.getPermissionStore()
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
        currentUser = intent.getStringExtra("current_user")
        permissions = intent.getStringExtra("permissions")
        parseAndSetRequest(intent)
        if (request != null || batchRequests != null) setupContent()
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
        val batch = batchRequests
        val currentRequest = if (batch != null && batch.isNotEmpty()) batch[0] else request ?: return
        val currentCallerPackage = callerPackage
        val currentCallerVerified = callerVerified
        val isBatch = batch != null && batch.size > 1

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
                        batchCount = if (isBatch) batch?.size else null,
                        onApprove = { duration ->
                            if (isBatch) handleBatchApprove(duration) else handleApprove(duration)
                        },
                        onReject = { duration -> handleReject(duration) }
                    )
                }
            }
        }
    }

    private fun parseAndSetRequest(intent: Intent) {
        val uri = intent.data?.toString() ?: return finishWithError("Invalid request")

        val batchJson = intent.getStringExtra("requests")
        if (batchJson != null) {
            batchRequests = parseBatchRequests(batchJson)
            if (batchRequests == null || batchRequests!!.isEmpty()) {
                return finishWithError("Invalid batch request")
            }
            return
        }

        var parsed = runCatching { handler?.parseIntentUri(uri) }.getOrNull()
            ?: return finishWithError("Invalid request")

        if (currentUser != null || permissions != null) {
            parsed = Nip55Request(
                requestType = parsed.requestType,
                content = parsed.content,
                pubkey = parsed.pubkey,
                returnType = parsed.returnType,
                compressionType = parsed.compressionType,
                callbackUrl = parsed.callbackUrl,
                id = parsed.id,
                currentUser = currentUser ?: parsed.currentUser,
                permissions = permissions ?: parsed.permissions
            )
        }
        request = parsed
        if (requestId.isNullOrBlank()) {
            requestId = parsed.id
        }
    }

    private fun parseBatchRequests(json: String): List<Nip55Request>? {
        return try {
            val h = handler ?: return null
            val array = org.json.JSONArray(json)
            val requests = mutableListOf<Nip55Request>()
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                val type = obj.getString("type")
                val content = obj.optString("content", "")
                val pubkey: String? = if (obj.has("pubkey")) obj.getString("pubkey") else null
                val id: String? = if (obj.has("id")) obj.getString("id") else null

                val requestType = when (type) {
                    "get_public_key" -> Nip55RequestType.GET_PUBLIC_KEY
                    "sign_event" -> Nip55RequestType.SIGN_EVENT
                    "nip04_encrypt" -> Nip55RequestType.NIP04_ENCRYPT
                    "nip04_decrypt" -> Nip55RequestType.NIP04_DECRYPT
                    "nip44_encrypt" -> Nip55RequestType.NIP44_ENCRYPT
                    "nip44_decrypt" -> Nip55RequestType.NIP44_DECRYPT
                    "decrypt_zap_event" -> Nip55RequestType.DECRYPT_ZAP_EVENT
                    else -> continue
                }

                requests.add(Nip55Request(
                    requestType = requestType,
                    content = content,
                    pubkey = pubkey,
                    returnType = "signature",
                    compressionType = "none",
                    callbackUrl = null,
                    id = id,
                    currentUser = currentUser,
                    permissions = permissions
                ))
            }
            requests
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse batch requests", e)
            null
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
                    Log.e(TAG, "Request failed: ${e.message}")
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

    private fun handleBatchApprove(duration: PermissionDuration) {
        val reqs = batchRequests ?: return
        val h = handler ?: return finishWithError("Handler not initialized")
        val callerId = callerPackage ?: "unknown"
        val store = permissionStore

        lifecycleScope.launch {
            val needsBiometric = reqs.any { it.requestType != Nip55RequestType.GET_PUBLIC_KEY }

            if (needsBiometric) {
                val authenticated = biometricHelper.authenticate(
                    title = "Approve Batch Request",
                    subtitle = "${reqs.size} operations"
                )
                if (!authenticated) {
                    finishWithError("Authentication failed")
                    return@launch
                }
            }

            if (store != null && callerId != "unknown") {
                reqs.forEach { req ->
                    val eventKind = if (req.requestType == Nip55RequestType.SIGN_EVENT) {
                        parseEventKind(req.content)
                    } else null
                    store.grantPermission(callerId, req.requestType, eventKind, duration)
                }
            }

            val result = withContext(Dispatchers.Default) {
                runCatching { h.handleBatchRequest(reqs, callerId) }
            }

            result.fold(
                onSuccess = { responses ->
                    if (store != null) {
                        reqs.forEach { req ->
                            val eventKind = if (req.requestType == Nip55RequestType.SIGN_EVENT) {
                                parseEventKind(req.content)
                            } else null
                            store.logOperation(callerId, req.requestType, eventKind, "allow", wasAutomatic = false)
                        }
                    }
                    finishWithBatchResult(responses)
                },
                onFailure = { e ->
                    val errorMsg = when (e) {
                        is KeepMobileException.RateLimited -> "rate_limited"
                        is KeepMobileException.NotInitialized -> "not_initialized"
                        is KeepMobileException.PubkeyMismatch -> "pubkey_mismatch"
                        is KeepMobileException.InvalidTimestamp -> "invalid_timestamp"
                        else -> "batch_request_failed"
                    }
                    Log.e(TAG, "Batch request failed: ${e.message}")
                    finishWithError(errorMsg)
                }
            )
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

    private fun finishWithBatchResult(responses: List<Nip55Response>) {
        val h = handler ?: return finishWithError("Handler not initialized")
        val resultsJson = h.serializeBatchResults(responses)
        val resultIntent = Intent().apply {
            putExtra("results", resultsJson)
            putExtra("package", packageName)
            requestId?.let { putExtra("id", it) }
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
