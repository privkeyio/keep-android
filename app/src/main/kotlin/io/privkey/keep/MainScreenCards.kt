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
import io.privkey.keep.storage.PinStore
import io.privkey.keep.storage.RelayConfigStore
import io.privkey.keep.uniffi.BunkerStatus
import io.privkey.keep.uniffi.PeerInfo
import io.privkey.keep.uniffi.PeerStatus
import io.privkey.keep.uniffi.ShareInfo

@Composable
fun PinSettingsCard(
    enabled: Boolean,
    onSetupPin: () -> Unit,
    onDisablePin: (String) -> Boolean
) {
    var showDisableDialog by remember { mutableStateOf(false) }
    var pinInput by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("PIN Protection", style = MaterialTheme.typography.titleMedium)
                Text(
                    if (enabled) "PIN is enabled" else "Secure app with PIN",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (enabled) {
                TextButton(onClick = { showDisableDialog = true }) {
                    Text("Disable", color = MaterialTheme.colorScheme.error)
                }
            } else {
                TextButton(onClick = onSetupPin) {
                    Text("Set Up")
                }
            }
        }
    }

    if (showDisableDialog) {
        AlertDialog(
            onDismissRequest = {
                showDisableDialog = false
                pinInput = ""
                error = null
            },
            title = { Text("Disable PIN?") },
            text = {
                Column {
                    Text("Enter your current PIN to disable protection.")
                    Spacer(modifier = Modifier.height(16.dp))
                    OutlinedTextField(
                        value = pinInput,
                        onValueChange = { newValue ->
                            if (newValue.length <= PinStore.MAX_PIN_LENGTH && newValue.all { it.isDigit() }) {
                                pinInput = newValue
                                error = null
                            }
                        },
                        label = { Text("Current PIN") },
                        singleLine = true,
                        visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword
                        ),
                        isError = error != null,
                        modifier = Modifier.fillMaxWidth()
                    )
                    error?.let {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = it,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (onDisablePin(pinInput)) {
                            showDisableDialog = false
                            pinInput = ""
                            error = null
                        } else {
                            error = "Incorrect PIN"
                            pinInput = ""
                        }
                    },
                    enabled = pinInput.length >= PinStore.MIN_PIN_LENGTH
                ) {
                    Text("Disable", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    showDisableDialog = false
                    pinInput = ""
                    error = null
                }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShareInfoCard(info: ShareInfo, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(info.name, style = MaterialTheme.typography.titleLarge)
            Spacer(modifier = Modifier.height(8.dp))
            Text("Share ${info.shareIndex} of ${info.totalShares}")
            Text("Threshold: ${info.threshold}")
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                "Group: ${info.groupPubkey.take(16)}...",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                "Tap for QR code",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary
            )
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
    val isOnline = peer.status == PeerStatus.ONLINE
    val statusText = when (peer.status) {
        PeerStatus.ONLINE -> "Online"
        PeerStatus.OFFLINE -> "Offline"
        PeerStatus.UNKNOWN -> "Unknown"
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text("Share ${peer.shareIndex}")
        Text(
            statusText,
            color = if (isOnline) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
fun RelaysCard(
    relays: List<String>,
    onAddRelay: (String) -> Unit,
    onRemoveRelay: (String) -> Unit
) {
    var showAddDialog by remember { mutableStateOf(false) }
    var newRelayUrl by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    fun dismissDialog() {
        showAddDialog = false
        newRelayUrl = ""
        error = null
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Relays", style = MaterialTheme.typography.titleMedium)
                IconButton(onClick = { showAddDialog = true }) {
                    Icon(Icons.Default.Add, contentDescription = "Add relay")
                }
            }
            if (relays.isEmpty()) {
                Text(
                    "No relays configured",
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
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
            }
        }
    }

    if (showAddDialog) {
        AlertDialog(
            onDismissRequest = ::dismissDialog,
            title = { Text("Add Relay") },
            text = {
                Column {
                    OutlinedTextField(
                        value = newRelayUrl,
                        onValueChange = {
                            newRelayUrl = it
                            error = null
                        },
                        label = { Text("Relay URL") },
                        placeholder = { Text("wss://relay.example.com") },
                        singleLine = true,
                        isError = error != null
                    )
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
                TextButton(onClick = {
                    val url = if (newRelayUrl.startsWith("wss://")) newRelayUrl else "wss://$newRelayUrl"
                    when {
                        url.length > 256 -> error = "URL too long"
                        !url.matches(RelayConfigStore.RELAY_URL_REGEX) -> error = "Invalid relay URL"
                        else -> {
                            val port = Regex(":(\\d{1,5})").find(url.removePrefix("wss://"))
                                ?.groupValues?.get(1)?.toIntOrNull()
                            if (port != null && port !in 1..65535) {
                                error = "Port must be between 1 and 65535"
                                return@TextButton
                            }
                            onAddRelay(url)
                            dismissDialog()
                        }
                    }
                }) {
                    Text("Add")
                }
            },
            dismissButton = {
                TextButton(onClick = ::dismissDialog) {
                    Text("Cancel")
                }
            }
        )
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
fun NoShareCard(onImport: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text("No FROST share stored")
            Spacer(modifier = Modifier.height(16.dp))
            Button(onClick = onImport) {
                Text("Import Share")
            }
        }
    }
}

@Composable
fun ErrorScreen(message: String) {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text(message, color = MaterialTheme.colorScheme.error)
    }
}

@Composable
fun KillSwitchCard(enabled: Boolean, onToggle: (Boolean) -> Unit) {
    val colors = MaterialTheme.colorScheme
    val containerColor = if (enabled) colors.errorContainer else colors.surfaceVariant
    val contentColor = if (enabled) colors.onErrorContainer else colors.onSurfaceVariant
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = if (enabled) "Signing Disabled" else "Kill Switch",
                    style = MaterialTheme.typography.titleMedium,
                    color = contentColor
                )
                if (enabled) {
                    Text(
                        text = "All signing requests blocked",
                        style = MaterialTheme.typography.bodySmall,
                        color = contentColor
                    )
                }
            }
            Switch(
                checked = enabled,
                onCheckedChange = onToggle,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = colors.error,
                    checkedTrackColor = containerColor
                )
            )
        }
    }
}

@Composable
fun SecurityLevelBadge(securityLevel: String) {
    val color = when (securityLevel) {
        "strongbox" -> MaterialTheme.colorScheme.primary
        "tee" -> MaterialTheme.colorScheme.secondary
        else -> MaterialTheme.colorScheme.error
    }
    Text(
        text = "Security: $securityLevel",
        style = MaterialTheme.typography.bodySmall,
        color = color
    )
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

@Composable
fun AutoStartCard(enabled: Boolean, onToggle: (Boolean) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Auto-start", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Reconnect relays on boot and network changes",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(checked = enabled, onCheckedChange = onToggle)
        }
    }
}

@Composable
fun ForegroundServiceCard(enabled: Boolean, onToggle: (Boolean) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Background Service", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Keep relay connections alive persistently",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(checked = enabled, onCheckedChange = onToggle)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BunkerCard(status: BunkerStatus, onClick: () -> Unit) {
    val statusText = when (status) {
        BunkerStatus.RUNNING -> "Running"
        BunkerStatus.STARTING -> "Starting..."
        BunkerStatus.ERROR -> "Error"
        BunkerStatus.STOPPED -> "Configure"
    }
    val statusColor = when (status) {
        BunkerStatus.RUNNING -> MaterialTheme.colorScheme.primary
        BunkerStatus.STARTING -> MaterialTheme.colorScheme.secondary
        BunkerStatus.ERROR -> MaterialTheme.colorScheme.error
        BunkerStatus.STOPPED -> MaterialTheme.colorScheme.onSurfaceVariant
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
