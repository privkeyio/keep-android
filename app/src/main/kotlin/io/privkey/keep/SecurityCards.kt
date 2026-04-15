package io.privkey.keep

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp

@Composable
fun KillSwitchCard(enabled: Boolean, onToggle: (Boolean) -> Unit, toggleEnabled: Boolean = true) {
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
                    text = if (enabled) stringResource(R.string.settings_kill_switch_active_title) else stringResource(R.string.settings_kill_switch_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = contentColor
                )
                if (enabled) {
                    Text(
                        text = stringResource(R.string.settings_kill_switch_active_subtitle),
                        style = MaterialTheme.typography.bodySmall,
                        color = contentColor
                    )
                }
            }
            Switch(
                checked = enabled,
                onCheckedChange = onToggle,
                enabled = toggleEnabled,
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
            text = stringResource(R.string.settings_security_level_label, securityLevel),
            style = MaterialTheme.typography.bodySmall,
            color = color
        )
        IconButton(
            onClick = { showBottomSheet = true },
            modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)
        ) {
            Icon(
                imageVector = Icons.Filled.Info,
                contentDescription = stringResource(R.string.settings_security_level_info_cd),
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
            text = stringResource(R.string.settings_security_level_title),
            style = MaterialTheme.typography.titleLarge
        )

        Spacer(modifier = Modifier.height(16.dp))

        val protectionText = when (currentLevel) {
            "strongbox", "tee" -> stringResource(R.string.settings_security_protection_hardware)
            "software" -> stringResource(R.string.settings_security_protection_software)
            else -> stringResource(R.string.settings_security_protection_unknown)
        }

        val descPrefix = stringResource(R.string.settings_security_description_prefix)
        val descSuffix = stringResource(R.string.settings_security_description_suffix)

        Text(
            text = buildAnnotatedString {
                append(descPrefix)
                withStyle(SpanStyle(fontWeight = FontWeight.Bold)) {
                    append(protectionText)
                }
                append(descSuffix)
            },
            style = MaterialTheme.typography.bodyMedium,
            color = colors.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(20.dp))

        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            SecurityLevelItem(
                title = stringResource(R.string.settings_security_strongbox_title),
                description = stringResource(R.string.settings_security_strongbox_desc),
                isCurrent = currentLevel == "strongbox",
                color = colors.primary
            )

            SecurityLevelItem(
                title = stringResource(R.string.settings_security_tee_title),
                description = stringResource(R.string.settings_security_tee_desc),
                isCurrent = currentLevel == "tee",
                color = colors.secondary
            )

            SecurityLevelItem(
                title = stringResource(R.string.settings_security_software_title),
                description = stringResource(R.string.settings_security_software_desc),
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
                            text = stringResource(R.string.settings_security_current_badge),
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
fun CertificatePinsCard(
    pins: List<CertificatePin>,
    onClearPin: (String) -> Unit,
    onClearAllPins: () -> Unit
) {
    var showClearAllDialog by remember { mutableStateOf(false) }
    var pinToDelete by remember { mutableStateOf<String?>(null) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(stringResource(R.string.settings_cert_pins_title), style = MaterialTheme.typography.titleMedium)
                if (pins.isNotEmpty()) {
                    TextButton(onClick = { showClearAllDialog = true }) {
                        Text(stringResource(R.string.settings_cert_pins_clear_all), color = MaterialTheme.colorScheme.error)
                    }
                }
            }
            if (pins.isEmpty()) {
                Text(
                    stringResource(R.string.settings_cert_pins_empty),
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
                                io.privkey.keep.uniffi.truncateStr(pin.spkiHash, 8u, 6u),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        IconButton(
                            onClick = { pinToDelete = pin.hostname },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = stringResource(R.string.settings_cert_pins_clear_cd),
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                }
            }
        }
    }

    pinToDelete?.let { hostname ->
        AlertDialog(
            onDismissRequest = { pinToDelete = null },
            title = { Text(stringResource(R.string.settings_cert_pins_clear_dialog_title)) },
            text = { Text(stringResource(R.string.settings_cert_pins_clear_dialog_text, hostname)) },
            confirmButton = {
                TextButton(onClick = {
                    onClearPin(hostname)
                    pinToDelete = null
                }) {
                    Text(stringResource(R.string.settings_cert_pins_clear), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { pinToDelete = null }) {
                    Text(stringResource(R.string.settings_cancel))
                }
            }
        )
    }

    if (showClearAllDialog) {
        AlertDialog(
            onDismissRequest = { showClearAllDialog = false },
            title = { Text(stringResource(R.string.settings_cert_pins_clear_all_dialog_title)) },
            text = { Text(stringResource(R.string.settings_cert_pins_clear_all_dialog_text)) },
            confirmButton = {
                TextButton(onClick = {
                    onClearAllPins()
                    showClearAllDialog = false
                }) {
                    Text(stringResource(R.string.settings_cert_pins_clear_all), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearAllDialog = false }) {
                    Text(stringResource(R.string.settings_cancel))
                }
            }
        )
    }
}
