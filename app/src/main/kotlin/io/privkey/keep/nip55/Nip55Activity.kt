package io.privkey.keep.nip55

import android.content.Intent
import android.os.Binder
import android.os.Bundle
import android.util.Log
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
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

private fun Nip55RequestType.displayName(): String = when (this) {
    Nip55RequestType.GET_PUBLIC_KEY -> "Get Public Key"
    Nip55RequestType.SIGN_EVENT -> "Sign Event"
    Nip55RequestType.NIP04_ENCRYPT -> "Encrypt (NIP-04)"
    Nip55RequestType.NIP04_DECRYPT -> "Decrypt (NIP-04)"
    Nip55RequestType.NIP44_ENCRYPT -> "Encrypt (NIP-44)"
    Nip55RequestType.NIP44_DECRYPT -> "Decrypt (NIP-44)"
    Nip55RequestType.DECRYPT_ZAP_EVENT -> "Decrypt Zap Event"
}

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

private fun parseEventKind(content: String): Int? = runCatching {
    org.json.JSONObject(content).optInt("kind", -1).takeIf { it >= 0 }
}.getOrNull()

private fun eventKindDescription(kind: Int): String = when (kind) {
    0 -> "Profile Metadata"
    1 -> "Short Text Note"
    3 -> "Contact List"
    4 -> "Encrypted DM"
    5 -> "Event Deletion"
    6 -> "Repost"
    7 -> "Reaction"
    in 10000..19999 -> "Replaceable Event"
    in 20000..29999 -> "Ephemeral Event"
    in 30000..39999 -> "Parameterized Replaceable"
    else -> "Kind $kind"
}

@Composable
fun ApprovalScreen(
    request: Nip55Request,
    callerPackage: String?,
    callerVerified: Boolean,
    batchCount: Int? = null,
    onApprove: (PermissionDuration) -> Unit,
    onReject: (PermissionDuration) -> Unit
) {
    var isLoading by remember { mutableStateOf(false) }
    var selectedDuration by remember { mutableStateOf(PermissionDuration.JUST_THIS_TIME) }
    var durationDropdownExpanded by remember { mutableStateOf(false) }
    val eventKind = remember(request) {
        if (request.requestType == Nip55RequestType.SIGN_EVENT) {
            parseEventKind(request.content)
        } else null
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = if (batchCount != null) "Batch Request ($batchCount)" else "Signing Request",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        CallerLabel(callerPackage, callerVerified)

        Spacer(modifier = Modifier.height(24.dp))

        RequestDetailsCard(request, eventKind)

        Spacer(modifier = Modifier.height(24.dp))

        DurationSelector(
            selectedDuration = selectedDuration,
            expanded = durationDropdownExpanded,
            onExpandedChange = { durationDropdownExpanded = it },
            onDurationSelected = { selectedDuration = it }
        )

        Spacer(modifier = Modifier.height(24.dp))

        if (isLoading) {
            CircularProgressIndicator()
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                OutlinedButton(
                    onClick = { onReject(selectedDuration) },
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Reject")
                }
                Button(
                    onClick = {
                        isLoading = true
                        onApprove(selectedDuration)
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Text(if (batchCount != null) "Approve All" else "Approve")
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DurationSelector(
    selectedDuration: PermissionDuration,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    onDurationSelected: (PermissionDuration) -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = "Remember this choice",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(4.dp))
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = onExpandedChange
        ) {
            OutlinedTextField(
                value = selectedDuration.displayName,
                onValueChange = {},
                readOnly = true,
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier
                    .fillMaxWidth()
                    .menuAnchor()
            )
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { onExpandedChange(false) }
            ) {
                PermissionDuration.entries.forEach { duration ->
                    DropdownMenuItem(
                        text = { Text(duration.displayName) },
                        onClick = {
                            onDurationSelected(duration)
                            onExpandedChange(false)
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun CallerLabel(callerPackage: String?, callerVerified: Boolean) {
    val errorColor = MaterialTheme.colorScheme.error
    if (callerPackage == null) {
        Text(
            text = "from unknown app",
            style = MaterialTheme.typography.bodySmall,
            color = errorColor
        )
        return
    }

    Text(
        text = "from $callerPackage",
        style = MaterialTheme.typography.bodySmall,
        color = if (callerVerified) MaterialTheme.colorScheme.onSurfaceVariant else errorColor
    )
    if (!callerVerified) {
        Text(
            text = "(unverified)",
            style = MaterialTheme.typography.labelSmall,
            color = errorColor
        )
    }
}

@Composable
private fun RequestDetailsCard(request: Nip55Request, eventKind: Int?) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            DetailRow("Type", request.requestType.displayName())

            eventKind?.let { kind ->
                Spacer(modifier = Modifier.height(16.dp))
                DetailRow("Event Kind", eventKindDescription(kind))
            }

            if (request.content.isNotEmpty() && request.requestType != Nip55RequestType.SIGN_EVENT) {
                val displayContent = request.content.take(200).let {
                    if (request.content.length > 200) "$it..." else it
                }
                Spacer(modifier = Modifier.height(16.dp))
                DetailRow("Content", displayContent, MaterialTheme.typography.bodyMedium)
            }

            request.pubkey?.let { pk ->
                Spacer(modifier = Modifier.height(16.dp))
                DetailRow("Recipient", "${pk.take(16)}...${pk.takeLast(8)}", MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun DetailRow(
    label: String,
    value: String,
    valueStyle: androidx.compose.ui.text.TextStyle = MaterialTheme.typography.bodyLarge
) {
    Text(
        text = label,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Text(text = value, style = valueStyle)
}
