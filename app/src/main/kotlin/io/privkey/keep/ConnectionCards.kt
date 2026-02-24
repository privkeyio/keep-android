package io.privkey.keep

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.privkey.keep.storage.RelayConfigStore
import io.privkey.keep.uniffi.BunkerStatus
import io.privkey.keep.uniffi.PeerInfo
import io.privkey.keep.uniffi.PeerStatus

@Composable
fun RelaysCard(
    relays: List<String>,
    onAddRelay: (String) -> Unit,
    onRemoveRelay: (String) -> Unit,
    profileRelays: List<String>,
    onAddProfileRelay: (String) -> Unit,
    onRemoveProfileRelay: (String) -> Unit
) {
    var showEditDialog by remember { mutableStateOf(false) }
    var showEditProfileDialog by remember { mutableStateOf(false) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Relays", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(12.dp))

            Text("Active relays", style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                "Manage the relays used for communication with external applications.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            if (relays.isEmpty()) {
                Text(
                    "No relays configured",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall
                )
            } else {
                relays.forEach { relay ->
                    RelayRow(relay)
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(
                onClick = { showEditDialog = true },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Edit Relays")
            }

            Spacer(modifier = Modifier.height(16.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(16.dp))

            Text("Default profile relays", style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                "Manage the relays used to fetch your profile data.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            if (profileRelays.isEmpty()) {
                Text(
                    "No profile relays configured",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall
                )
            } else {
                profileRelays.forEach { relay ->
                    RelayRow(relay)
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(
                onClick = { showEditProfileDialog = true },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Edit Profile Relays")
            }
        }
    }

    if (showEditDialog) {
        EditRelaysDialog(
            title = "Edit Relays",
            relays = relays,
            onAddRelay = onAddRelay,
            onRemoveRelay = onRemoveRelay,
            onDismiss = { showEditDialog = false }
        )
    }

    if (showEditProfileDialog) {
        EditRelaysDialog(
            title = "Edit Profile Relays",
            relays = profileRelays,
            onAddRelay = onAddProfileRelay,
            onRemoveRelay = onRemoveProfileRelay,
            onDismiss = { showEditProfileDialog = false }
        )
    }
}

@Composable
private fun RelayRow(relay: String) {
    Text(
        relay.removePrefix("wss://"),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        style = MaterialTheme.typography.bodyMedium
    )
}

@Composable
private fun EditRelaysDialog(
    title: String,
    relays: List<String>,
    onAddRelay: (String) -> Unit,
    onRemoveRelay: (String) -> Unit,
    onDismiss: () -> Unit
) {
    var newRelayUrl by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                relays.forEach { relay ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            relay.removePrefix("wss://"),
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodyMedium
                        )
                        IconButton(
                            onClick = { onRemoveRelay(relay) },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = "Remove",
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = newRelayUrl,
                        onValueChange = {
                            newRelayUrl = it
                            error = null
                        },
                        label = { Text("Relay URL") },
                        placeholder = { Text("wss://relay.example.com") },
                        singleLine = true,
                        isError = error != null,
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(onClick = {
                        val raw = newRelayUrl.trim()
                        if (raw.contains("://") && !raw.startsWith("wss://")) {
                            error = "Only wss:// URLs are supported"
                            return@IconButton
                        }
                        val url = if (raw.startsWith("wss://")) raw else "wss://$raw"
                        when {
                            url.length > 256 -> error = "URL too long"
                            !url.matches(RelayConfigStore.RELAY_URL_REGEX) -> error = "Invalid relay URL"
                            else -> {
                                if (!RelayConfigStore.isValidPort(url)) {
                                    error = "Port must be between 1 and 65535"
                                    return@IconButton
                                }
                                onAddRelay(url)
                                newRelayUrl = ""
                                error = null
                            }
                        }
                    }) {
                        Icon(Icons.Default.Add, contentDescription = "Add relay")
                    }
                }
                error?.let {
                    Text(
                        it,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Done")
            }
        }
    )
}

@Composable
fun ConnectCard(
    isConnected: Boolean,
    isConnecting: Boolean,
    error: String?,
    relaysConfigured: Boolean,
    onConnect: () -> Unit
) {
    val colors = MaterialTheme.colorScheme
    val (statusText, statusColor) = when {
        isConnecting -> "Connecting..." to colors.onSurfaceVariant
        isConnected -> "Connected to relays" to colors.primary
        error != null -> error to colors.error
        !relaysConfigured -> "Add relays first" to colors.onSurfaceVariant
        else -> "Not connected" to colors.onSurfaceVariant
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Connection", style = MaterialTheme.typography.titleMedium)
                    Text(statusText, style = MaterialTheme.typography.bodySmall, color = statusColor)
                }
                Button(
                    onClick = onConnect,
                    enabled = !isConnecting && !isConnected && relaysConfigured
                ) {
                    if (isConnecting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        Text(if (isConnected) "Connected" else "Connect")
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectedAppsCard(onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth(), onClick = onClick) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Connected Apps", style = MaterialTheme.typography.titleMedium)
            Text("Manage", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        }
    }
}

@Composable
fun PeersCard(peers: List<PeerInfo>) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Peers (${peers.size})", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            if (peers.isEmpty()) {
                Text("No peers connected", color = MaterialTheme.colorScheme.onSurfaceVariant)
            } else {
                peers.forEach { peer ->
                    PeerRow(peer)
                }
            }
        }
    }
}

@Composable
private fun PeerRow(peer: PeerInfo) {
    val colors = MaterialTheme.colorScheme
    val (statusText, statusColor) = when (peer.status) {
        PeerStatus.ONLINE -> "Online" to colors.primary
        PeerStatus.OFFLINE -> "Offline" to colors.onSurfaceVariant
        PeerStatus.UNKNOWN -> "Unknown" to colors.onSurfaceVariant
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text("Share ${peer.shareIndex}")
        Text(statusText, color = statusColor)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BunkerCard(status: BunkerStatus, onClick: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    val (statusText, statusColor) = when (status) {
        BunkerStatus.RUNNING -> "Running" to colors.primary
        BunkerStatus.STARTING -> "Starting..." to colors.secondary
        BunkerStatus.ERROR -> "Error" to colors.error
        BunkerStatus.STOPPED -> "Configure" to colors.onSurfaceVariant
    }
    Card(modifier = Modifier.fillMaxWidth(), onClick = onClick) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("NIP-46 Bunker", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Remote signing for web/desktop clients",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(statusText, style = MaterialTheme.typography.labelMedium, color = statusColor)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletDescriptorCard(descriptorCount: Int, onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth(), onClick = onClick) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Wallet Descriptors", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Manage multisig wallet descriptors",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(
                if (descriptorCount > 0) "$descriptorCount" else "Manage",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary
            )
        }
    }
}

@Composable
fun Nip55SettingsCard(
    onSignPolicyClick: () -> Unit,
    onPermissionsClick: () -> Unit,
    onHistoryClick: () -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("NIP-55 Settings", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(12.dp))
            OutlinedButton(
                onClick = onSignPolicyClick,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Sign Policy")
            }
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = onPermissionsClick,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Permissions")
                }
                OutlinedButton(
                    onClick = onHistoryClick,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("History")
                }
            }
        }
    }
}
