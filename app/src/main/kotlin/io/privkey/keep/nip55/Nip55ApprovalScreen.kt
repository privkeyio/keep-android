package io.privkey.keep.nip55

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
}

private fun Nip55RequestType.headerTitle(): String = when (this) {
    Nip55RequestType.GET_PUBLIC_KEY -> "Public Key Request"
    Nip55RequestType.SIGN_EVENT -> "Signing Request"
    Nip55RequestType.NIP44_ENCRYPT -> "Encryption Request"
    Nip55RequestType.NIP44_DECRYPT -> "Decryption Request"
    Nip55RequestType.NIP04_ENCRYPT -> "Encryption Request"
    Nip55RequestType.NIP04_DECRYPT -> "Decryption Request"
    Nip55RequestType.DECRYPT_ZAP_EVENT -> "Zap Decryption Request"
}

internal fun parseEventKind(content: String): Int? = runCatching {
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
            text = request.requestType.headerTitle(),
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
