package io.privkey.keep.nip46

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.privkey.keep.R
import io.privkey.keep.uniffi.formatPubkeyDisplay
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
            text = stringResource(R.string.connections_nostrconnect_title),
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = stringResource(R.string.connections_nostrconnect_from, request.name),
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
                text = stringResource(R.string.connections_nostrconnect_description),
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
                Nip46DetailRow(stringResource(R.string.connections_nostrconnect_client_pubkey), formatPubkeyDisplay(request.clientPubkey))

                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.connections_nostrconnect_relays),
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
                        text = stringResource(R.string.connections_nostrconnect_requested_permissions),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    request.permissions.forEach { perm ->
                        val permText = if (perm.kind != null) {
                            stringResource(R.string.connections_nostrconnect_permission_with_kind, formatNip46Method(perm.type), perm.kind.toString())
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
            label = stringResource(R.string.connections_nostrconnect_remember_permissions),
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
                    Text(stringResource(R.string.connections_nostrconnect_reject))
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
                    Text(stringResource(R.string.connections_nostrconnect_connect))
                }
            }
        }
    }
}

