package io.privkey.keep.nip46

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.privkey.keep.nip55.EventKind
import io.privkey.keep.nip55.PermissionDuration

private fun sanitizeDisplayContent(content: String): String {
    return content
        .replace(Regex("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]"), "\uFFFD")
        .replace(Regex("[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u206F\\uFEFF]"), "")
        .replace(Regex("[\\u0300-\\u036F]+"), "")
        .take(500)
}

@Composable
fun Nip46ApprovalScreen(
    appPubkey: String,
    appName: String,
    method: String,
    eventKind: Int?,
    eventContent: String?,
    isConnectRequest: Boolean = false,
    onApprove: (duration: PermissionDuration, onComplete: (success: Boolean) -> Unit) -> Unit,
    onReject: () -> Unit
) {
    var isLoading by remember { mutableStateOf(false) }
    var selectedDuration by remember { mutableStateOf(if (isConnectRequest) PermissionDuration.FOREVER else PermissionDuration.JUST_THIS_TIME) }
    var durationDropdownExpanded by remember { mutableStateOf(false) }
    val sanitizedContent = remember(eventContent) {
        eventContent?.let { sanitizeDisplayContent(it) }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = if (isConnectRequest) "New Connection Request" else "NIP-46 Request",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "from $appName",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        if (isConnectRequest) {
            Spacer(modifier = Modifier.height(12.dp))
            Surface(
                color = MaterialTheme.colorScheme.tertiaryContainer,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "This app is requesting to connect. Approving will authorize it for future signing requests.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onTertiaryContainer,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f, fill = false)
        ) {
            Column(
                modifier = Modifier
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Nip46DetailRow("Method", formatNip46Method(method))

                if (eventKind != null) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Nip46DetailRow("Event Kind", EventKind.displayName(eventKind))
                }

                if (!sanitizedContent.isNullOrBlank()) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "Content",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = sanitizedContent,
                        style = MaterialTheme.typography.bodyMedium,
                        maxLines = 10,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "App Public Key",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = formatNip46Pubkey(appPubkey),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        if (!isConnectRequest) {
            Spacer(modifier = Modifier.height(16.dp))
            PermissionDurationSelector(
                label = "Remember this decision",
                selectedDuration = selectedDuration,
                expanded = durationDropdownExpanded,
                onExpandedChange = { durationDropdownExpanded = it },
                onDurationSelected = { selectedDuration = it }
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
                    onClick = onReject,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Reject")
                }
                Button(
                    onClick = {
                        isLoading = true
                        onApprove(selectedDuration) { success ->
                            if (!success) {
                                isLoading = false
                            }
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Text(if (isConnectRequest) "Authorize" else "Approve")
                }
            }
        }
    }
}

