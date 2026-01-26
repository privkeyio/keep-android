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
    Nip55RequestType.NIP44_ENCRYPT -> "Encrypt (NIP-44)"
    Nip55RequestType.NIP44_DECRYPT -> "Decrypt (NIP-44)"
}

class Nip55Activity : FragmentActivity() {
    private lateinit var biometricHelper: BiometricHelper
    private var handler: Nip55Handler? = null
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
        handler = (application as? KeepMobileApp)?.getNip55Handler()
        identifyCaller()
        requestId = intent.getStringExtra("id")

        parseAndSetRequest(intent)

        if (request == null) return

        setupContent()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        identifyCaller()
        requestId = intent.getStringExtra("id")
        parseAndSetRequest(intent)

        if (request == null) return

        setupContent()
    }

    private fun identifyCaller() {
        val activity = callingActivity
        if (activity != null) {
            callerPackage = activity.packageName
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
        if (packages != null && packages.size == 1) {
            callerPackage = packages[0]
            callerVerified = true
        } else {
            callerPackage = packages?.firstOrNull()
            callerVerified = false
        }
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
                        onApprove = { handleApprove() },
                        onReject = { finishWithError("User rejected") }
                    )
                }
            }
        }
    }

    private fun parseAndSetRequest(intent: Intent) {
        val uri = intent.data?.toString() ?: return finishWithError("Invalid request")
        request = runCatching { handler?.parseIntentUri(uri) }.getOrNull()
            ?: return finishWithError("Invalid request")
    }

    private fun handleApprove() {
        val req = request ?: return
        val h = handler ?: return finishWithError("Handler not initialized")
        val callerId = callerPackage ?: "unknown"

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

            val result = withContext(Dispatchers.Default) {
                runCatching { h.handleRequest(req, callerId) }
            }

            result.fold(
                onSuccess = { response -> finishWithResult(response) },
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

    private fun finishWithResult(response: Nip55Response) {
        val resultIntent = Intent().apply {
            putExtra("result", response.result)
            putExtra("package", packageName)
            response.event?.let { putExtra("event", it) }
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

private fun parseEventKind(content: String): Int? {
    return runCatching {
        val json = org.json.JSONObject(content)
        json.optInt("kind", -1).takeIf { it >= 0 }
    }.getOrNull()
}

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
    onApprove: () -> Unit,
    onReject: () -> Unit
) {
    var isLoading by remember { mutableStateOf(false) }
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
            text = "Signing Request",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        if (callerPackage != null) {
            Text(
                text = "from $callerPackage",
                style = MaterialTheme.typography.bodySmall,
                color = if (callerVerified) {
                    MaterialTheme.colorScheme.onSurfaceVariant
                } else {
                    MaterialTheme.colorScheme.error
                }
            )
            if (!callerVerified) {
                Text(
                    text = "(unverified)",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        } else {
            Text(
                text = "from unknown app",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Type",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = request.requestType.displayName(),
                    style = MaterialTheme.typography.bodyLarge
                )

                eventKind?.let { kind ->
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "Event Kind",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = eventKindDescription(kind),
                        style = MaterialTheme.typography.bodyLarge
                    )
                }

                if (request.content.isNotEmpty() && request.requestType != Nip55RequestType.SIGN_EVENT) {
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "Content",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = if (request.content.length > 200) {
                            request.content.take(200) + "..."
                        } else {
                            request.content
                        },
                        style = MaterialTheme.typography.bodyMedium
                    )
                }

                request.pubkey?.let { pk ->
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "Recipient",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "${pk.take(16)}...${pk.takeLast(8)}",
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(32.dp))

        if (isLoading) {
            CircularProgressIndicator()
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                OutlinedButton(
                    onClick = onReject,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Reject")
                }
                Button(
                    onClick = {
                        isLoading = true
                        onApprove()
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Approve")
                }
            }
        }
    }
}
