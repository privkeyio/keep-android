package io.privkey.keep.nip55

import android.content.Intent
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
    private var callerPackage: String = "unknown"

    companion object {
        private const val TAG = "Nip55Activity"
        private const val GENERIC_ERROR_MESSAGE = "An error occurred"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        biometricHelper = BiometricHelper(this)
        handler = (application as? KeepMobileApp)?.getNip55Handler()
        callerPackage = callingActivity?.packageName ?: "unknown"
        requestId = intent.getStringExtra("id")

        parseAndSetRequest(intent)

        if (request == null) return

        setupContent()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        callerPackage = callingActivity?.packageName ?: "unknown"
        requestId = intent.getStringExtra("id")
        parseAndSetRequest(intent)

        if (request == null) return

        setupContent()
    }

    private fun setupContent() {
        setContent {
            KeepAndroidTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    request?.let { req ->
                        ApprovalScreen(
                            request = req,
                            callerPackage = callerPackage,
                            onApprove = { handleApprove() },
                            onReject = { finishWithError("User rejected") }
                        )
                    }
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

            val response = withContext(Dispatchers.Default) {
                runCatching { h.handleRequest(req) }.getOrNull()
            }
            if (response != null) {
                finishWithResult(response)
            } else {
                finishWithError("Request failed")
            }
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

@Composable
fun ApprovalScreen(
    request: Nip55Request,
    callerPackage: String,
    onApprove: () -> Unit,
    onReject: () -> Unit
) {
    var isLoading by remember { mutableStateOf(false) }

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

        Text(
            text = "from $callerPackage",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

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

                if (request.content.isNotEmpty()) {
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
