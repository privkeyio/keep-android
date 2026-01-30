package io.privkey.keep.nip55

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType

internal fun Nip55RequestType.displayName(): String = when (this) {
    Nip55RequestType.GET_PUBLIC_KEY -> "Get Public Key"
    Nip55RequestType.SIGN_EVENT -> "Sign Event"
    Nip55RequestType.NIP44_ENCRYPT -> "Encrypt (NIP-44)"
    Nip55RequestType.NIP44_DECRYPT -> "Decrypt (NIP-44)"
    Nip55RequestType.NIP04_ENCRYPT -> "Encrypt (NIP-04)"
    Nip55RequestType.NIP04_DECRYPT -> "Decrypt (NIP-04)"
    Nip55RequestType.DECRYPT_ZAP_EVENT -> "Decrypt Zap Event"
    else -> name.replace("_", " ").lowercase().replaceFirstChar { it.uppercase() }
}

private fun Nip55RequestType.headerTitle(): String = when (this) {
    Nip55RequestType.GET_PUBLIC_KEY -> "Public Key Request"
    Nip55RequestType.SIGN_EVENT -> "Signing Request"
    Nip55RequestType.NIP44_ENCRYPT, Nip55RequestType.NIP04_ENCRYPT -> "Encryption Request"
    Nip55RequestType.NIP44_DECRYPT, Nip55RequestType.NIP04_DECRYPT -> "Decryption Request"
    Nip55RequestType.DECRYPT_ZAP_EVENT -> "Zap Decryption Request"
    else -> "${displayName()} Request"
}

internal fun parseEventKind(content: String): Int? = runCatching {
    org.json.JSONObject(content).optInt("kind", -1).takeIf { it in 0..65535 }
}.getOrNull()

@Composable
fun ApprovalScreen(
    request: Nip55Request,
    callerPackage: String?,
    callerVerified: Boolean,
    onApprove: (PermissionDuration) -> Unit,
    onReject: (PermissionDuration) -> Unit
) {
    var isLoading by remember { mutableStateOf(false) }
    val canRememberChoice = callerVerified && callerPackage != null
    var selectedDuration by remember { mutableStateOf(PermissionDuration.JUST_THIS_TIME) }
    var durationDropdownExpanded by remember { mutableStateOf(false) }
    val eventKind = remember(request) {
        if (request.requestType == Nip55RequestType.SIGN_EVENT) parseEventKind(request.content) else null
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = request.requestType.headerTitle(),
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        CallerLabel(callerPackage, callerVerified)

        if (!callerVerified) {
            Spacer(modifier = Modifier.height(8.dp))
            UnverifiedCallerWarning()
        }

        Spacer(modifier = Modifier.height(24.dp))

        RequestDetailsCard(request, eventKind)

        Spacer(modifier = Modifier.height(24.dp))

        if (canRememberChoice) {
            DurationSelector(
                selectedDuration = selectedDuration,
                expanded = durationDropdownExpanded,
                onExpandedChange = { durationDropdownExpanded = it },
                onDurationSelected = { selectedDuration = it },
                isSensitiveKind = eventKind?.let { isSensitiveKind(it) } ?: false
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        if (isLoading) {
            CircularProgressIndicator()
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                OutlinedButton(
                    onClick = { onReject(if (canRememberChoice) selectedDuration else PermissionDuration.JUST_THIS_TIME) },
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Reject")
                }
                Button(
                    onClick = {
                        isLoading = true
                        onApprove(if (canRememberChoice) selectedDuration else PermissionDuration.JUST_THIS_TIME)
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Approve")
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
    onDurationSelected: (PermissionDuration) -> Unit,
    isSensitiveKind: Boolean = false
) {
    val availableDurations = if (isSensitiveKind) {
        PermissionDuration.entries.filter { it != PermissionDuration.FOREVER }
    } else {
        PermissionDuration.entries
    }

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
                value = stringResource(selectedDuration.displayNameRes),
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
                availableDurations.forEach { duration ->
                    DropdownMenuItem(
                        text = { Text(stringResource(duration.displayNameRes)) },
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
    val displayText = if (callerPackage != null) "from $callerPackage" else "from unknown app"
    val isUntrusted = callerPackage == null || !callerVerified
    val textColor = if (isUntrusted) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant

    Text(
        text = displayText,
        style = MaterialTheme.typography.bodySmall,
        color = textColor
    )
}

@Composable
private fun UnverifiedCallerWarning() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Text(
            text = "Warning: Unable to verify the requesting app. Only approve if you initiated this action.",
            modifier = Modifier.padding(12.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onErrorContainer
        )
    }
}

@Composable
private fun RequestDetailsCard(request: Nip55Request, eventKind: Int?) {
    var showFullContent by remember { mutableStateOf(false) }
    val contentTruncated = request.content.length > 200

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            DetailRow("Type", request.requestType.displayName())

            eventKind?.let { kind ->
                Spacer(modifier = Modifier.height(16.dp))
                DetailRow("Event Kind", eventKindName(kind))
                sensitiveKindWarning(kind)?.let { warning ->
                    Spacer(modifier = Modifier.height(8.dp))
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer
                        )
                    ) {
                        Text(
                            text = warning,
                            modifier = Modifier.padding(8.dp),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }

            if (request.content.isNotEmpty() && request.requestType != Nip55RequestType.SIGN_EVENT) {
                val shouldTruncate = !showFullContent && contentTruncated
                val displayContent = if (shouldTruncate) "${request.content.take(200)}..." else request.content
                Spacer(modifier = Modifier.height(16.dp))
                DetailRow("Content", displayContent, MaterialTheme.typography.bodyMedium)
                if (contentTruncated) {
                    TextButton(
                        onClick = { showFullContent = !showFullContent },
                        modifier = Modifier.padding(top = 4.dp)
                    ) {
                        Text(if (showFullContent) "Show less" else "Show full content")
                    }
                }
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
    valueStyle: TextStyle = MaterialTheme.typography.bodyLarge
) {
    Text(
        text = label,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Text(text = value, style = valueStyle)
}
