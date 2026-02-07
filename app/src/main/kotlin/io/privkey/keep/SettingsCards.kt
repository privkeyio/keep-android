package io.privkey.keep

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.privkey.keep.storage.BiometricTimeoutStore
import io.privkey.keep.storage.PinStore
import io.privkey.keep.storage.ProxyConfigStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun PinSettingsCard(
    enabled: Boolean,
    onSetupPin: () -> Unit,
    onDisablePin: suspend (String) -> Boolean
) {
    val coroutineScope = rememberCoroutineScope()
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
                        coroutineScope.launch {
                            val disabled = withContext(Dispatchers.IO) {
                                onDisablePin(pinInput)
                            }
                            if (disabled) {
                                showDisableDialog = false
                                pinInput = ""
                                error = null
                            } else {
                                error = "Incorrect PIN"
                                pinInput = ""
                            }
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
