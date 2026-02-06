package io.privkey.keep

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import io.privkey.keep.storage.BiometricTimeoutStore
import io.privkey.keep.storage.PinStore
import io.privkey.keep.storage.ProxyConfigStore
import io.privkey.keep.storage.RelayConfigStore
import io.privkey.keep.uniffi.BunkerStatus
import io.privkey.keep.uniffi.CertificatePin
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
                    val raw = newRelayUrl.trim()
                    val url = if (raw.startsWith("wss://")) raw else "wss://$raw"
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
    Box(modifier = Modifier.fillMaxSize().statusBarsPadding(), contentAlignment = Alignment.Center) {
        Text(message, color = MaterialTheme.colorScheme.error)
    }
}

@Composable
fun KillSwitchCard(enabled: Boolean, onToggle: (Boolean) -> Unit) {
    val colors = MaterialTheme.colorScheme
    val (containerColor, contentColor) = if (enabled) {
        colors.errorContainer to colors.onErrorContainer
    } else {
        colors.surfaceVariant to colors.onSurfaceVariant
    }
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityLevelBadge(securityLevel: String) {
    var showBottomSheet by remember { mutableStateOf(false) }
    val sheetState = rememberModalBottomSheetState()
    val colors = MaterialTheme.colorScheme

    val color = when (securityLevel) {
        "strongbox" -> colors.primary
        "tee" -> colors.secondary
        else -> colors.error
    }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(
            text = "Security: $securityLevel",
            style = MaterialTheme.typography.bodySmall,
            color = color
        )
        IconButton(
            onClick = { showBottomSheet = true },
            modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)
        ) {
            Icon(
                imageVector = Icons.Filled.Info,
                contentDescription = "Security level info",
                modifier = Modifier.size(16.dp),
                tint = color
            )
        }
    }

    if (showBottomSheet) {
        ModalBottomSheet(
            onDismissRequest = { showBottomSheet = false },
            sheetState = sheetState
        ) {
            SecurityLevelInfoContent(currentLevel = securityLevel)
        }
    }
}

@Composable
private fun SecurityLevelInfoContent(currentLevel: String) {
    val colors = MaterialTheme.colorScheme

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 24.dp)
            .padding(bottom = 32.dp)
    ) {
        Text(
            text = "Security Level",
            style = MaterialTheme.typography.titleLarge
        )

        Spacer(modifier = Modifier.height(16.dp))

        val protectionText = when (currentLevel) {
            "strongbox", "tee" -> "hardware security"
            "software" -> "software encryption"
            else -> "an unknown protection level"
        }

        Text(
            text = buildAnnotatedString {
                append("Your encryption keys are protected by ")
                withStyle(SpanStyle(fontWeight = FontWeight.Bold)) {
                    append(protectionText)
                }
                append(". This determines how securely your Nostr private keys are stored.")
            },
            style = MaterialTheme.typography.bodyMedium,
            color = colors.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(20.dp))

        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            SecurityLevelItem(
                title = "StrongBox",
                description = "Dedicated security chip (HSM). Highest protection - keys never leave secure hardware.",
                isCurrent = currentLevel == "strongbox",
                color = colors.primary
            )

            SecurityLevelItem(
                title = "Trusted Execution Environment",
                description = "Secure area of main processor, isolated from regular OS.",
                isCurrent = currentLevel == "tee",
                color = colors.secondary
            )

            SecurityLevelItem(
                title = "Software",
                description = "Software-only protection. Less secure but still encrypted.",
                isCurrent = currentLevel == "software",
                color = colors.error
            )
        }
    }
}

@Composable
private fun SecurityLevelItem(
    title: String,
    description: String,
    isCurrent: Boolean,
    color: Color
) {
    val colors = MaterialTheme.colorScheme
    val backgroundColor = if (isCurrent) color.copy(alpha = 0.12f) else colors.surfaceVariant.copy(alpha = 0.5f)

    Surface(
        shape = MaterialTheme.shapes.medium,
        color = backgroundColor,
        border = if (isCurrent) BorderStroke(2.dp, color) else null
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    color = if (isCurrent) color else colors.onSurface
                )
                if (isCurrent) {
                    Spacer(modifier = Modifier.width(8.dp))
                    Badge(containerColor = color) {
                        Text(
                            text = "CURRENT",
                            modifier = Modifier.padding(horizontal = 2.dp)
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = colors.onSurfaceVariant
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
                Text("Foreground Service", style = MaterialTheme.typography.titleMedium)
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
fun BiometricTimeoutCard(
    currentTimeout: Long,
    onTimeoutChanged: (Long) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Biometric Re-auth", style = MaterialTheme.typography.titleMedium)
                Text(
                    "How often to require biometric authentication",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            ExposedDropdownMenuBox(
                expanded = expanded,
                onExpandedChange = { expanded = it }
            ) {
                OutlinedTextField(
                    value = BiometricTimeoutStore.formatTimeout(currentTimeout),
                    onValueChange = {},
                    readOnly = true,
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                    modifier = Modifier
                        .menuAnchor()
                        .width(140.dp),
                    textStyle = MaterialTheme.typography.bodySmall,
                    singleLine = true
                )
                ExposedDropdownMenu(
                    expanded = expanded,
                    onDismissRequest = { expanded = false }
                ) {
                    BiometricTimeoutStore.TIMEOUT_OPTIONS.forEach { timeout ->
                        DropdownMenuItem(
                            text = { Text(BiometricTimeoutStore.formatTimeout(timeout)) },
                            onClick = {
                                onTimeoutChanged(timeout)
                                expanded = false
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun ProxySettingsCard(
    enabled: Boolean,
    host: String,
    port: Int,
    onToggle: (Boolean) -> Unit,
    onConfigChange: (String, Int) -> Unit
) {
    var showConfigDialog by remember { mutableStateOf(false) }
    var hostInput by remember(host) { mutableStateOf(host) }
    var portInput by remember(port) { mutableStateOf(port.toString()) }
    var error by remember { mutableStateOf<String?>(null) }

    fun dismissDialog() {
        showConfigDialog = false
        hostInput = host
        portInput = port.toString()
        error = null
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("SOCKS Proxy", style = MaterialTheme.typography.titleMedium)
                    Text(
                        if (enabled) "$host:$port" else "Route connections through Tor",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(checked = enabled, onCheckedChange = onToggle)
            }
            if (enabled) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = { onConfigChange("127.0.0.1", 9050) },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Tor (9050)")
                    }
                    OutlinedButton(
                        onClick = { showConfigDialog = true },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Configure")
                    }
                }
            }
        }
    }

    if (showConfigDialog) {
        AlertDialog(
            onDismissRequest = ::dismissDialog,
            title = { Text("Configure Proxy") },
            text = {
                Column {
                    OutlinedTextField(
                        value = hostInput,
                        onValueChange = {
                            hostInput = it
                            error = null
                        },
                        label = { Text("Host") },
                        placeholder = { Text("127.0.0.1") },
                        singleLine = true,
                        isError = error != null
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = portInput,
                        onValueChange = { value ->
                            if (value.isEmpty() || value.all { it.isDigit() }) {
                                portInput = value
                                error = null
                            }
                        },
                        label = { Text("Port") },
                        placeholder = { Text("9050") },
                        singleLine = true,
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.Number
                        ),
                        isError = error != null
                    )
                    error?.let {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            it,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        "Only localhost addresses allowed",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val newHost = hostInput.trim()
                    val newPort = portInput.toIntOrNull()
                    if (!ProxyConfigStore.isValidHost(newHost)) {
                        error = "Host must be localhost"
                    } else if (newPort == null || !ProxyConfigStore.isValidPort(newPort)) {
                        error = "Port must be 1-65535"
                    } else {
                        onConfigChange(newHost, newPort)
                        dismissDialog()
                    }
                }) {
                    Text("Save")
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

@Composable
fun CertificatePinsCard(
    pins: List<CertificatePin>,
    onClearPin: (String) -> Unit,
    onClearAllPins: () -> Unit
) {
    var showClearAllDialog by remember { mutableStateOf(false) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Certificate Pins", style = MaterialTheme.typography.titleMedium)
                if (pins.isNotEmpty()) {
                    TextButton(onClick = { showClearAllDialog = true }) {
                        Text("Clear All", color = MaterialTheme.colorScheme.error)
                    }
                }
            }
            if (pins.isEmpty()) {
                Text(
                    "Pins are set on first connection to each relay",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall
                )
            } else {
                pins.forEach { pin ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                pin.hostname,
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Text(
                                pin.spkiHash.take(16) + "...",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        IconButton(
                            onClick = { onClearPin(pin.hostname) },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = "Clear pin",
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                }
            }
        }
    }

    if (showClearAllDialog) {
        AlertDialog(
            onDismissRequest = { showClearAllDialog = false },
            title = { Text("Clear All Pins?") },
            text = { Text("This will remove all stored certificate pins. New pins will be set on next connection.") },
            confirmButton = {
                TextButton(onClick = {
                    onClearAllPins()
                    showClearAllDialog = false
                }) {
                    Text("Clear All", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearAllDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}
