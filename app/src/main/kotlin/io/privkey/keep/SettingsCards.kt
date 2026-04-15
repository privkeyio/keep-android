package io.privkey.keep

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.privkey.keep.storage.BiometricTimeoutStore
import io.privkey.keep.storage.PinStore
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
    val incorrectPinMsg = stringResource(R.string.settings_pin_incorrect)

    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.settings_pin_title), style = MaterialTheme.typography.titleMedium)
                Text(
                    if (enabled) stringResource(R.string.settings_pin_enabled) else stringResource(R.string.settings_pin_disabled_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (enabled) {
                TextButton(onClick = { showDisableDialog = true }) {
                    Text(stringResource(R.string.settings_pin_disable), color = MaterialTheme.colorScheme.error)
                }
            } else {
                TextButton(onClick = onSetupPin) {
                    Text(stringResource(R.string.settings_pin_set_up))
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
            title = { Text(stringResource(R.string.settings_pin_disable_dialog_title)) },
            text = {
                Column {
                    Text(stringResource(R.string.settings_pin_disable_dialog_text))
                    Spacer(modifier = Modifier.height(16.dp))
                    OutlinedTextField(
                        value = pinInput,
                        onValueChange = { newValue ->
                            if (newValue.length <= PinStore.MAX_PIN_LENGTH && newValue.all { it.isDigit() }) {
                                pinInput = newValue
                                error = null
                            }
                        },
                        label = { Text(stringResource(R.string.settings_pin_current_label)) },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.NumberPassword
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
                                error = incorrectPinMsg
                                pinInput = ""
                            }
                        }
                    },
                    enabled = pinInput.length >= PinStore.MIN_PIN_LENGTH
                ) {
                    Text(stringResource(R.string.settings_pin_disable), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    showDisableDialog = false
                    pinInput = ""
                    error = null
                }) {
                    Text(stringResource(R.string.settings_cancel))
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
                Text(stringResource(R.string.settings_auto_start_title), style = MaterialTheme.typography.titleMedium)
                Text(
                    stringResource(R.string.settings_auto_start_subtitle),
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
                Text(stringResource(R.string.settings_foreground_service_title), style = MaterialTheme.typography.titleMedium)
                Text(
                    stringResource(R.string.settings_foreground_service_subtitle),
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
                Text(stringResource(R.string.settings_biometric_reauth_title), style = MaterialTheme.typography.titleMedium)
                Text(
                    stringResource(R.string.settings_biometric_reauth_subtitle),
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
                        .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable)
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
fun TorOrbotCard(
    enabled: Boolean,
    port: Int,
    onActivate: (Int) -> Unit,
    onDeactivate: () -> Unit
) {
    var portInput by remember(port) { mutableStateOf(port.toString()) }
    var error by remember { mutableStateOf<String?>(null) }
    val portRangeError = stringResource(R.string.settings_tor_port_range_error)

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(stringResource(R.string.settings_tor_title), style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                stringResource(R.string.settings_tor_subtitle),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(12.dp))

            val steps = listOf(
                stringResource(R.string.settings_tor_step_install),
                stringResource(R.string.settings_tor_step_start),
                stringResource(R.string.settings_tor_step_check_port),
                stringResource(R.string.settings_tor_step_change_port),
                stringResource(R.string.settings_tor_step_configure),
                stringResource(R.string.settings_tor_step_activate)
            )
            steps.forEachIndexed { index, step ->
                Text(
                    stringResource(R.string.settings_tor_step_format, index + 1, step),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(12.dp))
            OutlinedTextField(
                value = portInput,
                onValueChange = { value ->
                    if (value.isEmpty() || value.all { it.isDigit() }) {
                        portInput = value
                        error = null
                    }
                },
                label = { Text(stringResource(R.string.settings_tor_socks_port_label)) },
                placeholder = { Text(stringResource(R.string.settings_tor_socks_port_placeholder)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Number
                ),
                isError = error != null,
                modifier = Modifier.fillMaxWidth()
            )
            error?.let {
                Spacer(modifier = Modifier.height(4.dp))
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }

            Spacer(modifier = Modifier.height(12.dp))
            if (enabled) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        stringResource(R.string.settings_tor_proxy_active, port),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                    OutlinedButton(onClick = onDeactivate) {
                        Text(stringResource(R.string.settings_tor_deactivate))
                    }
                }
            } else {
                Button(
                    onClick = {
                        val p = portInput.toIntOrNull()
                        if (p == null || p !in 1..65535) {
                            error = portRangeError
                        } else {
                            onActivate(p)
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(stringResource(R.string.settings_tor_activate))
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportLogsCard(onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth(), onClick = onClick) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.settings_export_logs_title), style = MaterialTheme.typography.titleMedium)
                Text(
                    stringResource(R.string.settings_export_logs_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(stringResource(R.string.settings_export_logs_action), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackupSettingsCard(onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth(), onClick = onClick) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.settings_backup_title), style = MaterialTheme.typography.titleMedium)
                Text(
                    stringResource(R.string.settings_backup_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(stringResource(R.string.settings_backup_action), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        }
    }
}
