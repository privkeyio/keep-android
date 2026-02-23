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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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

private fun parseBunkerUrlRelays(input: String): List<String>? {
    if (!input.startsWith("bunker://")) return null
    val uri = runCatching { java.net.URI(input) }.getOrNull() ?: return null
    val query = uri.rawQuery ?: return null
    return query.split("&")
        .filter { it.startsWith("relay=") }
        .mapNotNull { param ->
            runCatching {
                java.net.URLDecoder.decode(param.removePrefix("relay="), Charsets.UTF_8)
            }.getOrNull()
        }
        .filter { it.startsWith("wss://") }
        .distinct()
        .ifEmpty { null }
}

private fun normalizeRelayUrl(input: String): String {
    val stripped = input
        .removePrefix("https://")
        .removePrefix("http://")
        .removePrefix("ws://")
    return if (stripped.startsWith("wss://")) stripped else "wss://$stripped"
}

private suspend fun addBunkerRelays(
    bunkerRelays: List<String>,
    existingRelays: List<String>,
): Result<List<String>> {
    val validRelays = bunkerRelays.filter { validateRelayUrl(it, existingRelays) == null }
    val safeRelays = withContext(Dispatchers.IO) {
        validRelays.filter { !BunkerConfigStore.isInternalHost(it) }
    }
    val remaining = BunkerConfigStore.MAX_RELAYS - existingRelays.size

    if (remaining <= 0) return Result.failure(Exception("Maximum relays reached"))

    val toAdd = safeRelays.take(remaining)
    if (toAdd.isEmpty()) {
        val message = when {
            bunkerRelays.all { existingRelays.contains(it) } -> "Relays already added"
            validRelays.isNotEmpty() && safeRelays.isEmpty() ->
                "Private/internal relay addresses are not allowed"
            else -> "No valid relay URLs found in bunker URL"
        }
        return Result.failure(Exception(message))
    }

    return Result.success(toAdd)
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
    val scope = rememberCoroutineScope()
    var relays by remember { mutableStateOf(bunkerConfigStore.getRelays()) }
    var authorizedClients by remember { mutableStateOf(bunkerConfigStore.getAuthorizedClients()) }
    var showAddDialog by remember { mutableStateOf(false) }
    var showRevokeAllDialog by remember { mutableStateOf(false) }
    val isEnabled = bunkerStatus == BunkerStatus.RUNNING || bunkerStatus == BunkerStatus.STARTING

    DisposableEffect(Unit) {
        setSecureScreen(context, true)
        onDispose {
            setSecureScreen(context, false)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
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
                scope.launch { bunkerConfigStore.setRelays(updated) }
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
        AddBunkerRelayDialog(
            relays = relays,
            onRelaysUpdated = { updated ->
                relays = updated
                scope.launch { bunkerConfigStore.setRelays(updated) }
            },
            onDismiss = { showAddDialog = false }
        )
    }

    if (showRevokeAllDialog) {
        RevokeAllClientsDialog(
            onConfirm = {
                bunkerConfigStore.revokeAllClients()
                authorizedClients = emptySet()
                Toast.makeText(context, "All clients revoked", Toast.LENGTH_SHORT).show()
            },
            onDismiss = { showRevokeAllDialog = false }
        )
    }
}

@Composable
private fun AddBunkerRelayDialog(
    relays: List<String>,
    onRelaysUpdated: (List<String>) -> Unit,
    onDismiss: () -> Unit
) {
    val scope = rememberCoroutineScope()
    var newRelayUrl by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    fun dismissDialog() {
        newRelayUrl = ""
        error = null
        onDismiss()
    }

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
                    placeholder = { Text("wss://relay.example.com or bunker://...") },
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
                val trimmed = newRelayUrl.trim()
                val bunkerRelays = parseBunkerUrlRelays(trimmed)

                when {
                    bunkerRelays != null -> scope.launch {
                        addBunkerRelays(bunkerRelays, relays).fold(
                            onSuccess = { toAdd ->
                                onRelaysUpdated(relays + toAdd)
                                dismissDialog()
                            },
                            onFailure = { error = it.message }
                        )
                    }
                    trimmed.startsWith("bunker://") ->
                        error = "No relay URLs found in bunker URL"
                    else -> {
                        val url = normalizeRelayUrl(trimmed)
                        val validationError = validateRelayUrl(url, relays)
                        if (validationError != null) {
                            error = validationError
                        } else {
                            scope.launch {
                                val isInternal = withContext(Dispatchers.IO) {
                                    BunkerConfigStore.isInternalHost(url)
                                }
                                if (isInternal) {
                                    error = "Internal/private hosts are not allowed"
                                } else {
                                    onRelaysUpdated(relays + url)
                                    dismissDialog()
                                }
                            }
                        }
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

@Composable
private fun RevokeAllClientsDialog(
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Revoke All Clients") },
        text = {
            Text("This will disconnect all authorized clients. They will need to reconnect and be approved again.")
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onConfirm()
                    onDismiss()
                },
                colors = ButtonDefaults.textButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                )
            ) {
                Text("Revoke All")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
private fun StatusBadge(status: BunkerStatus) {
    val (statusText, statusColor) = when (status) {
        BunkerStatus.RUNNING -> "Running" to MaterialTheme.colorScheme.primary
        BunkerStatus.STARTING -> "Starting..." to MaterialTheme.colorScheme.secondary
        BunkerStatus.ERROR -> "Error" to MaterialTheme.colorScheme.error
        BunkerStatus.STOPPED -> "Stopped" to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Text(
        text = statusText,
        style = MaterialTheme.typography.labelLarge,
        color = statusColor
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
