package io.privkey.keep

import io.privkey.keep.ui.components.KeepCard
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
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

    KeepCard(contentPadding = PaddingValues(0.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(stringResource(R.string.connections_relays_title), style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(12.dp))

            Text(stringResource(R.string.connections_relays_active_title), style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                stringResource(R.string.connections_relays_active_description),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            if (relays.isEmpty()) {
                Text(
                    stringResource(R.string.connections_relays_none),
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
                Text(stringResource(R.string.connections_relays_edit_button))
            }

            Spacer(modifier = Modifier.height(16.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(16.dp))

            Text(stringResource(R.string.connections_relays_profile_title), style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                stringResource(R.string.connections_relays_profile_description),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            if (profileRelays.isEmpty()) {
                Text(
                    stringResource(R.string.connections_relays_profile_none),
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
                Text(stringResource(R.string.connections_relays_profile_edit_button))
            }
        }
    }

    if (showEditDialog) {
        EditRelaysDialog(
            title = stringResource(R.string.connections_relays_dialog_edit_title),
            relays = relays,
            onAddRelay = onAddRelay,
            onRemoveRelay = onRemoveRelay,
            onDismiss = { showEditDialog = false }
        )
    }

    if (showEditProfileDialog) {
        EditRelaysDialog(
            title = stringResource(R.string.connections_relays_dialog_edit_profile_title),
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
    val errWssOnly = stringResource(R.string.connections_relays_error_wss_only)
    val errTooLong = stringResource(R.string.connections_relays_error_too_long)
    val errInvalid = stringResource(R.string.connections_relays_error_invalid)
    val errPort = stringResource(R.string.connections_relays_error_port)

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
                                contentDescription = stringResource(R.string.connections_relays_remove_cd),
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
                        label = { Text(stringResource(R.string.connections_relays_url_label)) },
                        placeholder = { Text(stringResource(R.string.connections_relays_url_placeholder)) },
                        singleLine = true,
                        isError = error != null,
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(onClick = {
                        val raw = newRelayUrl.trim()
                        if (raw.contains("://") && !raw.startsWith("wss://")) {
                            error = errWssOnly
                            return@IconButton
                        }
                        val url = if (raw.startsWith("wss://")) raw else "wss://$raw"
                        when {
                            url.length > 256 -> error = errTooLong
                            !url.matches(RELAY_URL_REGEX) -> error = errInvalid
                            else -> {
                                if (!isValidRelayPort(url)) {
                                    error = errPort
                                    return@IconButton
                                }
                                onAddRelay(url)
                                newRelayUrl = ""
                                error = null
                            }
                        }
                    }) {
                        Icon(Icons.Default.Add, contentDescription = stringResource(R.string.connections_relays_add_cd))
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
                Text(stringResource(R.string.connections_relays_done))
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
    val connecting = stringResource(R.string.connections_connect_connecting)
    val connectedToRelays = stringResource(R.string.connections_connect_connected_to_relays)
    val addRelaysFirst = stringResource(R.string.connections_connect_add_relays_first)
    val notConnected = stringResource(R.string.connections_connect_not_connected)
    val (statusText, statusColor) = when {
        isConnecting -> connecting to colors.onSurfaceVariant
        isConnected -> connectedToRelays to colors.primary
        error != null -> error to colors.error
        !relaysConfigured -> addRelaysFirst to colors.onSurfaceVariant
        else -> notConnected to colors.onSurfaceVariant
    }

    KeepCard(contentPadding = PaddingValues(0.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.connections_connect_title), style = MaterialTheme.typography.titleMedium)
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
                        Text(if (isConnected) stringResource(R.string.connections_connect_button_connected) else stringResource(R.string.connections_connect_button_connect))
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
            Text(stringResource(R.string.connections_connected_apps_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.connections_connected_apps_manage), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        }
    }
}

@Composable
fun PeersCard(peers: List<PeerInfo>) {
    KeepCard(contentPadding = PaddingValues(0.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(stringResource(R.string.connections_peers_title, peers.size), style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            if (peers.isEmpty()) {
                Text(stringResource(R.string.connections_peers_none), color = MaterialTheme.colorScheme.onSurfaceVariant)
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
    val online = stringResource(R.string.connections_peer_status_online)
    val offline = stringResource(R.string.connections_peer_status_offline)
    val unknown = stringResource(R.string.connections_peer_status_unknown)
    val (statusText, statusColor) = when (peer.status) {
        PeerStatus.ONLINE -> online to colors.primary
        PeerStatus.OFFLINE -> offline to colors.onSurfaceVariant
        PeerStatus.UNKNOWN -> unknown to colors.onSurfaceVariant
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(stringResource(R.string.connections_peer_share, peer.shareIndex.toString()))
        Text(statusText, color = statusColor)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BunkerCard(status: BunkerStatus, onClick: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    val running = stringResource(R.string.connections_bunker_status_running)
    val starting = stringResource(R.string.connections_bunker_status_starting)
    val errorText = stringResource(R.string.connections_bunker_status_error)
    val configure = stringResource(R.string.connections_bunker_status_configure)
    val (statusText, statusColor) = when (status) {
        BunkerStatus.RUNNING -> running to colors.primary
        BunkerStatus.STARTING -> starting to colors.secondary
        BunkerStatus.ERROR -> errorText to colors.error
        BunkerStatus.STOPPED -> configure to colors.onSurfaceVariant
    }
    Card(modifier = Modifier.fillMaxWidth(), onClick = onClick) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.connections_bunker_title), style = MaterialTheme.typography.titleMedium)
                Text(
                    stringResource(R.string.connections_bunker_subtitle),
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
                Text(stringResource(R.string.connections_wallet_title), style = MaterialTheme.typography.titleMedium)
                Text(
                    stringResource(R.string.connections_wallet_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(
                if (descriptorCount > 0) stringResource(R.string.connections_wallet_count, descriptorCount) else stringResource(R.string.connections_wallet_manage),
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
    onHistoryClick: () -> Unit,
    onRelayAuthWhitelistClick: () -> Unit
) {
    KeepCard(contentPadding = PaddingValues(0.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(stringResource(R.string.connections_nip55_settings_title), style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(12.dp))
            OutlinedButton(
                onClick = onSignPolicyClick,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.connections_nip55_sign_policy))
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(
                onClick = onRelayAuthWhitelistClick,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.connections_nip55_relay_auth_whitelist))
            }
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = onPermissionsClick,
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)
                ) {
                    Text(stringResource(R.string.connections_nip55_permissions), maxLines = 1)
                }
                OutlinedButton(
                    onClick = onHistoryClick,
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)
                ) {
                    Text(stringResource(R.string.connections_nip55_history), maxLines = 1)
                }
            }
        }
    }
}
