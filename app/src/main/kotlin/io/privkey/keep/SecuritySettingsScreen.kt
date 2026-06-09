package io.privkey.keep

import io.privkey.keep.ui.components.KeepCard
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecuritySettingsScreen(
    pinEnabled: Boolean,
    onSetupPin: () -> Unit,
    onDisablePin: suspend (String) -> Boolean,
    biometricTimeout: Long,
    onTimeoutChanged: (Long) -> Unit,
    biometricLockOnLaunch: Boolean,
    onBiometricLockOnLaunchChanged: (Boolean) -> Unit,
    biometricAvailable: Boolean,
    killSwitchEnabled: Boolean,
    onKillSwitchToggle: (Boolean) -> Unit,
    onExportLogs: () -> Unit,
    onViewActivityLog: () -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current

    DisposableEffect(context) {
        setSecureScreen(context, true)
        onDispose { setSecureScreen(context, false) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_security_screen_title)) },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.settings_back_cd))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            KillSwitchCard(
                enabled = killSwitchEnabled,
                onToggle = onKillSwitchToggle,
                toggleEnabled = biometricAvailable
            )

            PinSettingsCard(
                enabled = pinEnabled,
                onSetupPin = onSetupPin,
                onDisablePin = onDisablePin
            )

            BiometricTimeoutCard(
                currentTimeout = biometricTimeout,
                onTimeoutChanged = onTimeoutChanged
            )

            BiometricLockOnLaunchCard(
                enabled = biometricLockOnLaunch,
                onToggle = onBiometricLockOnLaunchChanged,
                biometricAvailable = biometricAvailable
            )

            ActivityLogCard(onClick = onViewActivityLog)

            ExportLogsCard(onClick = onExportLogs)

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun BiometricLockOnLaunchCard(
    enabled: Boolean,
    onToggle: (Boolean) -> Unit,
    biometricAvailable: Boolean
) {
    KeepCard(contentPadding = PaddingValues(0.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.settings_biometric_on_launch_title), style = MaterialTheme.typography.titleMedium)
                val (subtitle, subtitleColor) = if (biometricAvailable) {
                    stringResource(R.string.settings_biometric_on_launch_subtitle) to MaterialTheme.colorScheme.onSurfaceVariant
                } else {
                    stringResource(R.string.settings_biometric_unavailable) to MaterialTheme.colorScheme.error
                }
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = subtitleColor)
            }
            Switch(
                checked = enabled,
                onCheckedChange = onToggle,
                enabled = biometricAvailable
            )
        }
    }
}
