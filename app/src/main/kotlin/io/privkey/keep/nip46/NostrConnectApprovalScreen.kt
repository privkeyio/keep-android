package io.privkey.keep.nip46

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.privkey.keep.formatPubkeyDisplay
import io.privkey.keep.nip55.PermissionDuration

@Composable
fun NostrConnectApprovalScreen(
    request: NostrConnectRequest,
    onApprove: (PermissionDuration, onComplete: (Boolean) -> Unit) -> Unit,
    onReject: () -> Unit
) {
    var isLoading by remember { mutableStateOf(false) }
    var selectedDuration by remember { mutableStateOf(PermissionDuration.JUST_THIS_TIME) }
    var durationDropdownExpanded by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Connection Request",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "from ${request.name}",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(12.dp))

        Surface(
            color = MaterialTheme.colorScheme.tertiaryContainer,
            shape = MaterialTheme.shapes.small,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = "This app wants to connect via NIP-46. Approving will authorize it to send signing requests.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onTertiaryContainer,
                modifier = Modifier.padding(12.dp)
            )
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
                Nip46DetailRow("Client Pubkey", formatPubkeyDisplay(request.clientPubkey))

                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "Relays",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                request.relays.forEach { relay ->
                    Text(
                        text = relay.removePrefix("wss://"),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }

                if (request.permissions.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "Requested Permissions",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    request.permissions.forEach { perm ->
                        val permText = if (perm.kind != null) {
                            "${formatNip46Method(perm.type)} (kind ${perm.kind})"
                        } else {
                            formatNip46Method(perm.type)
                        }
                        Text(
                            text = permText,
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        PermissionDurationSelector(
            label = "Remember permissions",
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
                    Text("Connect")
                }
            }
        }
    }
}

