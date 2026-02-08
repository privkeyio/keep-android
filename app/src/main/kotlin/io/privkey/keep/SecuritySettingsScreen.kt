package io.privkey.keep

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
    killSwitchEnabled: Boolean,
    onKillSwitchToggle: (Boolean) -> Unit,
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
                title = { Text("Security") },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
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
                onToggle = onKillSwitchToggle
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
                onToggle = onBiometricLockOnLaunchChanged
            )

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
fun BiometricLockOnLaunchCard(enabled: Boolean, onToggle: (Boolean) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Biometric on Launch", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Require biometric authentication when opening app",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(checked = enabled, onCheckedChange = onToggle)
        }
    }
}
