package io.privkey.keep.nip46

import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.privkey.keep.QrCodeDisplay
import io.privkey.keep.copySensitiveText
import io.privkey.keep.setSecureScreen
import io.privkey.keep.storage.BunkerConfigStore
import io.privkey.keep.uniffi.BunkerStatus

private fun validateRelayUrl(url: String, existingRelays: List<String>): String? = when {
    url.length > 256 -> "URL too long"
    !url.matches(BunkerConfigStore.RELAY_URL_REGEX) -> "Invalid relay URL"
    existingRelays.size >= BunkerConfigStore.MAX_RELAYS -> "Maximum relays reached"
    existingRelays.contains(url) -> "Relay already added"
    else -> null
}

@Composable
fun BunkerScreen(
    bunkerConfigStore: BunkerConfigStore,
    bunkerUrl: String?,
    bunkerStatus: BunkerStatus,
    onToggleBunker: (Boolean) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    var relays by remember { mutableStateOf(bunkerConfigStore.getRelays()) }
    var authorizedClients by remember { mutableStateOf(bunkerConfigStore.getAuthorizedClients()) }
    var showAddDialog by remember { mutableStateOf(false) }
    var showRevokeAllDialog by remember { mutableStateOf(false) }
    var newRelayUrl by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val isEnabled = bunkerStatus == BunkerStatus.RUNNING || bunkerStatus == BunkerStatus.STARTING

    DisposableEffect(Unit) {
        setSecureScreen(context, true)
        onDispose {
            setSecureScreen(context, false)
        }
    }

    fun dismissDialog() {
        showAddDialog = false
        newRelayUrl = ""
        error = null
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "NIP-46 Bunker",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        StatusBadge(bunkerStatus)

        Spacer(modifier = Modifier.height(16.dp))

        if (bunkerUrl != null && bunkerStatus == BunkerStatus.RUNNING) {
            QrCodeDisplay(
                data = bunkerUrl,
                label = "Bunker URL",
                onCopied = {
                    Toast.makeText(context, "Bunker URL copied", Toast.LENGTH_SHORT).show()
                }
            )

            Spacer(modifier = Modifier.height(8.dp))

            OutlinedButton(
                onClick = {
                    copySensitiveText(context, bunkerUrl)
                    Toast.makeText(context, "Bunker URL copied", Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Copy Bunker URL")
            }

            Spacer(modifier = Modifier.height(16.dp))
        }

        BunkerToggleCard(
            enabled = isEnabled,
            canEnable = relays.isNotEmpty(),
            onToggle = { enabled ->
                if (enabled && relays.isEmpty()) {
                    Toast.makeText(context, "Add at least one relay first", Toast.LENGTH_SHORT).show()
                    return@BunkerToggleCard
                }
                bunkerConfigStore.setEnabled(enabled)
                onToggleBunker(enabled)
            }
        )

        Spacer(modifier = Modifier.height(16.dp))

        BunkerRelaysCard(
            relays = relays,
            isEnabled = isEnabled,
            onAddClick = { showAddDialog = true },
            onRemove = { relay ->
                val updated = relays - relay
                relays = updated
                bunkerConfigStore.setRelays(updated)
            }
        )

        Spacer(modifier = Modifier.height(16.dp))

        AuthorizedClientsCard(
            clients = authorizedClients,
            onRevoke = { pubkey ->
                bunkerConfigStore.revokeClient(pubkey)
                authorizedClients = bunkerConfigStore.getAuthorizedClients()
                Toast.makeText(context, "Client revoked", Toast.LENGTH_SHORT).show()
            },
            onRevokeAll = { showRevokeAllDialog = true }
        )

        Spacer(modifier = Modifier.height(24.dp))

        TextButton(
            onClick = onDismiss,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Back")
        }
    }

    if (showAddDialog) {
        AlertDialog(
            onDismissRequest = ::dismissDialog,
            title = { Text("Add Bunker Relay") },
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
                    val validationError = validateRelayUrl(url, relays)
                    if (validationError != null) {
                        error = validationError
                    } else {
                        val updated = relays + url
                        relays = updated
                        bunkerConfigStore.setRelays(updated)
                        dismissDialog()
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

    if (showRevokeAllDialog) {
        AlertDialog(
            onDismissRequest = { showRevokeAllDialog = false },
            title = { Text("Revoke All Clients") },
            text = {
                Text("This will disconnect all authorized clients. They will need to reconnect and be approved again.")
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        bunkerConfigStore.revokeAllClients()
                        authorizedClients = emptySet()
                        showRevokeAllDialog = false
                        Toast.makeText(context, "All clients revoked", Toast.LENGTH_SHORT).show()
                    },
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Text("Revoke All")
                }
            },
            dismissButton = {
                TextButton(onClick = { showRevokeAllDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Composable
private fun StatusBadge(status: BunkerStatus) {
    val (text, color) = when (status) {
        BunkerStatus.RUNNING -> "Running" to MaterialTheme.colorScheme.primary
        BunkerStatus.STARTING -> "Starting..." to MaterialTheme.colorScheme.secondary
        BunkerStatus.ERROR -> "Error" to MaterialTheme.colorScheme.error
        BunkerStatus.STOPPED -> "Stopped" to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Text(
        text = text,
        style = MaterialTheme.typography.labelLarge,
        color = color
    )
}

@Composable
private fun BunkerToggleCard(
    enabled: Boolean,
    canEnable: Boolean,
    onToggle: (Boolean) -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Bunker Mode", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Accept remote signing requests",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(
                checked = enabled,
                onCheckedChange = onToggle,
                enabled = canEnable || enabled
            )
        }
    }
}

@Composable
private fun BunkerRelaysCard(
    relays: List<String>,
    isEnabled: Boolean,
    onAddClick: () -> Unit,
    onRemove: (String) -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Bunker Relays", style = MaterialTheme.typography.titleMedium)
                IconButton(onClick = onAddClick, enabled = !isEnabled) {
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
                            onClick = { onRemove(relay) },
                            modifier = Modifier.size(24.dp),
                            enabled = !isEnabled
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
}

@Composable
private fun AuthorizedClientsCard(
    clients: Set<String>,
    onRevoke: (String) -> Unit,
    onRevokeAll: () -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Authorized Clients", style = MaterialTheme.typography.titleMedium)
                if (clients.isNotEmpty()) {
                    TextButton(
                        onClick = onRevokeAll,
                        colors = ButtonDefaults.textButtonColors(
                            contentColor = MaterialTheme.colorScheme.error
                        )
                    ) {
                        Text("Revoke All", style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                "Clients that have been approved to connect",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            if (clients.isEmpty()) {
                Text(
                    "No authorized clients",
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                clients.forEach { pubkey ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "${pubkey.take(8)}...${pubkey.takeLast(6)}",
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodySmall
                        )
                        IconButton(
                            onClick = { onRevoke(pubkey) },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = "Revoke",
                                modifier = Modifier.size(16.dp),
                                tint = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            }
        }
    }
}
