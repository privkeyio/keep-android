package io.privkey.keep

import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.setContent
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
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.privkey.keep.nip55.AppPermissionsScreen
import io.privkey.keep.nip55.ConnectedAppsScreen
import io.privkey.keep.nip55.PermissionStore
import io.privkey.keep.nip55.PermissionsManagementScreen
import io.privkey.keep.nip55.SigningHistoryScreen
import io.privkey.keep.nip55.SignPolicyScreen
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.AutoStartStore
import io.privkey.keep.storage.ForegroundServiceStore
import io.privkey.keep.storage.KillSwitchStore
import io.privkey.keep.storage.PinStore
import io.privkey.keep.storage.RelayConfigStore
import io.privkey.keep.storage.SignPolicyStore
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.PeerInfo
import io.privkey.keep.uniffi.PeerStatus
import io.privkey.keep.uniffi.ShareInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.crypto.Cipher

class MainActivity : FragmentActivity() {
    private val biometricHelper by lazy { BiometricHelper(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val app = application as KeepMobileApp
        val keepMobile = app.getKeepMobile()
        val storage = app.getStorage()
        val relayConfigStore = app.getRelayConfigStore()
        val killSwitchStore = app.getKillSwitchStore()
        val signPolicyStore = app.getSignPolicyStore()
        val autoStartStore = app.getAutoStartStore()
        val foregroundServiceStore = app.getForegroundServiceStore()
        val pinStore = app.getPinStore()
        val permissionStore = app.getPermissionStore()

        val allDependenciesAvailable = keepMobile != null &&
            storage != null &&
            relayConfigStore != null &&
            killSwitchStore != null &&
            signPolicyStore != null &&
            autoStartStore != null &&
            foregroundServiceStore != null &&
            pinStore != null &&
            permissionStore != null

        setContent {
            var isPinUnlocked by remember {
                mutableStateOf(pinStore?.isSessionValid() ?: true)
            }
            KeepAndroidTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    if (pinStore != null && pinStore.isPinEnabled() && !isPinUnlocked) {
                        PinUnlockScreen(
                            pinStore = pinStore,
                            onUnlocked = { isPinUnlocked = true }
                        )
                    } else if (allDependenciesAvailable) {
                        MainScreen(
                            keepMobile = keepMobile!!,
                            storage = storage!!,
                            relayConfigStore = relayConfigStore!!,
                            killSwitchStore = killSwitchStore!!,
                            signPolicyStore = signPolicyStore!!,
                            autoStartStore = autoStartStore!!,
                            foregroundServiceStore = foregroundServiceStore!!,
                            pinStore = pinStore!!,
                            permissionStore = permissionStore!!,
                            securityLevel = storage.getSecurityLevel(),
                            lifecycleOwner = this@MainActivity,
                            onRelaysChanged = { relays ->
                                app.initializeWithRelays(relays) { error ->
                                    lifecycleScope.launch {
                                        Toast.makeText(
                                            this@MainActivity,
                                            error,
                                            Toast.LENGTH_SHORT
                                        ).show()
                                    }
                                }
                            },
                            onBiometricRequest = { title, subtitle, cipher, callback ->
                                lifecycleScope.launch {
                                    try {
                                        val authedCipher = biometricHelper.authenticateWithCrypto(
                                            cipher, title, subtitle
                                        )
                                        callback(authedCipher)
                                    } catch (e: Exception) {
                                        Toast.makeText(
                                            this@MainActivity,
                                            "Authentication failed",
                                            Toast.LENGTH_SHORT
                                        ).show()
                                        callback(null)
                                    }
                                }
                            },
                            onBiometricAuth = {
                                biometricHelper.authenticate(
                                    title = "Disable Kill Switch",
                                    subtitle = "Authenticate to re-enable signing"
                                )
                            },
                            onAutoStartChanged = { enabled ->
                                app.updateNetworkMonitoring(enabled)
                            },
                            onForegroundServiceChanged = { enabled ->
                                app.updateForegroundService(enabled)
                            }
                        )
                    } else {
                        ErrorScreen("Failed to initialize")
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    keepMobile: KeepMobile,
    storage: AndroidKeystoreStorage,
    relayConfigStore: RelayConfigStore,
    killSwitchStore: KillSwitchStore,
    signPolicyStore: SignPolicyStore,
    autoStartStore: AutoStartStore,
    foregroundServiceStore: ForegroundServiceStore,
    pinStore: PinStore,
    permissionStore: PermissionStore,
    securityLevel: String,
    lifecycleOwner: LifecycleOwner,
    onRelaysChanged: (List<String>) -> Unit,
    onBiometricRequest: (String, String, Cipher, (Cipher?) -> Unit) -> Unit,
    onBiometricAuth: (suspend () -> Boolean)? = null,
    onAutoStartChanged: (Boolean) -> Unit = {},
    onForegroundServiceChanged: (Boolean) -> Unit = {}
) {
    var hasShare by remember { mutableStateOf(keepMobile.hasShare()) }
    var shareInfo by remember { mutableStateOf(keepMobile.getShareInfo()) }
    var peers by remember { mutableStateOf<List<PeerInfo>>(emptyList()) }
    var pendingCount by remember { mutableStateOf(0) }
    var showImportScreen by remember { mutableStateOf(false) }
    var showShareDetails by remember { mutableStateOf(false) }
    var showExportScreen by remember { mutableStateOf(false) }
    var showPermissionsScreen by remember { mutableStateOf(false) }
    var showHistoryScreen by remember { mutableStateOf(false) }
    var showSignPolicyScreen by remember { mutableStateOf(false) }
    var importState by remember { mutableStateOf<ImportState>(ImportState.Idle) }
    val coroutineScope = rememberCoroutineScope()
    var relays by remember { mutableStateOf(relayConfigStore.getRelays()) }
    var killSwitchEnabled by remember { mutableStateOf(killSwitchStore.isEnabled()) }
    var autoStartEnabled by remember { mutableStateOf(autoStartStore.isEnabled()) }
    var foregroundServiceEnabled by remember { mutableStateOf(foregroundServiceStore.isEnabled()) }
    var showKillSwitchConfirmDialog by remember { mutableStateOf(false) }
    var showConnectedApps by remember { mutableStateOf(false) }
    var selectedAppPackage by remember { mutableStateOf<String?>(null) }
    var showPinSetup by remember { mutableStateOf(false) }
    var pinEnabled by remember { mutableStateOf(pinStore.isPinEnabled()) }

    LaunchedEffect(Unit) {
        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                hasShare = keepMobile.hasShare()
                shareInfo = keepMobile.getShareInfo()
                if (hasShare) {
                    peers = keepMobile.getPeers()
                    pendingCount = keepMobile.getPendingRequests().size
                }
                delay(2000)
            }
        }
    }

    if (showPinSetup) {
        PinSetupScreen(
            pinStore = pinStore,
            onPinSet = {
                pinEnabled = true
                showPinSetup = false
            },
            onDismiss = { showPinSetup = false }
        )
        return
    }

    if (showSignPolicyScreen) {
        SignPolicyScreen(
            signPolicyStore = signPolicyStore,
            onDismiss = { showSignPolicyScreen = false }
        )
        return
    }

    if (showPermissionsScreen) {
        PermissionsManagementScreen(
            permissionStore = permissionStore,
            onDismiss = { showPermissionsScreen = false }
        )
        return
    }

    if (showHistoryScreen) {
        SigningHistoryScreen(
            permissionStore = permissionStore,
            onDismiss = { showHistoryScreen = false }
        )
        return
    }

    val currentShareInfoForScreens = shareInfo
    if (showExportScreen && currentShareInfoForScreens != null) {
        ExportShareScreen(
            keepMobile = keepMobile,
            shareInfo = currentShareInfoForScreens,
            storage = storage,
            onGetCipher = { storage.getCipherForDecryption() },
            onBiometricAuth = { cipher, callback ->
                onBiometricRequest("Export Share", "Authenticate to export share", cipher, callback)
            },
            onDismiss = { showExportScreen = false }
        )
        return
    }

    if (showShareDetails && currentShareInfoForScreens != null) {
        ShareDetailsScreen(
            shareInfo = currentShareInfoForScreens,
            onExport = {
                showShareDetails = false
                showExportScreen = true
            },
            onDismiss = { showShareDetails = false }
        )
        return
    }

    if (showConnectedApps) {
        selectedAppPackage?.let { pkg ->
            AppPermissionsScreen(
                packageName = pkg,
                permissionStore = permissionStore,
                signPolicyStore = signPolicyStore,
                onDismiss = { selectedAppPackage = null }
            )
            return
        }

        ConnectedAppsScreen(
            permissionStore = permissionStore,
            onAppClick = { selectedAppPackage = it },
            onDismiss = { showConnectedApps = false }
        )
        return
    }

    if (showImportScreen) {
        ImportShareScreen(
            onImport = { data, passphrase, name, cipher ->
                importState = ImportState.Importing
                if (!isValidKshareFormat(data)) {
                    importState = ImportState.Error("Invalid share format")
                    return@ImportShareScreen
                }
                coroutineScope.launch {
                    storage.setPendingCipher(cipher)
                    try {
                        val result = withContext(Dispatchers.IO) {
                            keepMobile.importShare(data, passphrase, name)
                        }
                        importState = ImportState.Success(result.name)
                        hasShare = keepMobile.hasShare()
                        shareInfo = keepMobile.getShareInfo()
                    } catch (e: Exception) {
                        Log.e("MainActivity", "Import failed: ${e::class.simpleName}")
                        importState = ImportState.Error("Import failed. Please try again.")
                    } finally {
                        storage.clearPendingCipher()
                    }
                }
            },
            onGetCipher = { storage.getCipherForEncryption() },
            onBiometricAuth = { cipher, callback ->
                onBiometricRequest("Import Share", "Authenticate to store share securely", cipher, callback)
            },
            onDismiss = {
                showImportScreen = false
                importState = ImportState.Idle
            },
            importState = importState
        )
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Keep",
            style = MaterialTheme.typography.headlineLarge
        )

        Spacer(modifier = Modifier.height(4.dp))

        SecurityLevelBadge(securityLevel)

        Spacer(modifier = Modifier.height(16.dp))

        KillSwitchCard(
            enabled = killSwitchEnabled,
            onToggle = { newValue ->
                if (newValue) {
                    showKillSwitchConfirmDialog = true
                } else {
                    coroutineScope.launch {
                        val authenticated = onBiometricAuth?.invoke() ?: true
                        if (authenticated) {
                            withContext(Dispatchers.IO) { killSwitchStore.setEnabled(false) }
                            killSwitchEnabled = false
                        }
                    }
                }
            }
        )

        if (showKillSwitchConfirmDialog) {
            AlertDialog(
                onDismissRequest = { showKillSwitchConfirmDialog = false },
                title = { Text("Enable Kill Switch?") },
                text = { Text("This will block all signing requests until you disable it. You will need biometric authentication to re-enable signing.") },
                confirmButton = {
                    TextButton(onClick = {
                        coroutineScope.launch {
                            withContext(Dispatchers.IO) { killSwitchStore.setEnabled(true) }
                            killSwitchEnabled = true
                            showKillSwitchConfirmDialog = false
                        }
                    }) {
                        Text("Enable")
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showKillSwitchConfirmDialog = false }) {
                        Text("Cancel")
                    }
                }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        val currentShareInfo = shareInfo
        if (hasShare && currentShareInfo != null) {
            ShareInfoCard(
                info = currentShareInfo,
                onClick = { showShareDetails = true }
            )

            Spacer(modifier = Modifier.height(16.dp))

            RelaysCard(
                relays = relays,
                onAddRelay = { relay ->
                    if (!relays.contains(relay) && relays.size < RelayConfigStore.MAX_RELAYS) {
                        val updated = relays + relay
                        relays = updated
                        onRelaysChanged(updated)
                    }
                },
                onRemoveRelay = { relay ->
                    val updated = relays - relay
                    relays = updated
                    onRelaysChanged(updated)
                }
            )

            Spacer(modifier = Modifier.height(16.dp))

            ConnectedAppsCard(onClick = { showConnectedApps = true })

            Spacer(modifier = Modifier.height(16.dp))

            PeersCard(peers)

            if (pendingCount > 0) {
                Spacer(modifier = Modifier.height(16.dp))
                Badge { Text("$pendingCount pending") }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Nip55SettingsCard(
                onSignPolicyClick = { showSignPolicyScreen = true },
                onPermissionsClick = { showPermissionsScreen = true },
                onHistoryClick = { showHistoryScreen = true }
            )

        } else {
            NoShareCard(
                onImport = { showImportScreen = true }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        AutoStartCard(
            enabled = autoStartEnabled,
            onToggle = { newValue ->
                coroutineScope.launch {
                    withContext(Dispatchers.IO) { autoStartStore.setEnabled(newValue) }
                    autoStartEnabled = newValue
                    onAutoStartChanged(newValue)
                }
            }
        )

        Spacer(modifier = Modifier.height(16.dp))

        ForegroundServiceCard(
            enabled = foregroundServiceEnabled,
            onToggle = { newValue ->
                coroutineScope.launch {
                    withContext(Dispatchers.IO) { foregroundServiceStore.setEnabled(newValue) }
                    foregroundServiceEnabled = newValue
                    onForegroundServiceChanged(newValue)
                }
            }
        )

        Spacer(modifier = Modifier.height(16.dp))

        PinSettingsCard(
            enabled = pinEnabled,
            onSetupPin = { showPinSetup = true },
            onDisablePin = {
                pinStore.disablePin()
                pinEnabled = false
            }
        )
    }
}

@Composable
private fun PinSettingsCard(
    enabled: Boolean,
    onSetupPin: () -> Unit,
    onDisablePin: () -> Unit
) {
    var showDisableDialog by remember { mutableStateOf(false) }

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
            onDismissRequest = { showDisableDialog = false },
            title = { Text("Disable PIN?") },
            text = { Text("This will remove PIN protection from the app.") },
            confirmButton = {
                TextButton(onClick = {
                    onDisablePin()
                    showDisableDialog = false
                }) {
                    Text("Disable", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showDisableDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ShareInfoCard(info: ShareInfo, onClick: () -> Unit) {
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
private fun PeersCard(peers: List<PeerInfo>) {
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
private fun ConnectedAppsCard(onClick: () -> Unit) {
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
private fun NoShareCard(onImport: () -> Unit) {
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
private fun ErrorScreen(message: String) {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text(message, color = MaterialTheme.colorScheme.error)
    }
}

@Composable
private fun KillSwitchCard(enabled: Boolean, onToggle: (Boolean) -> Unit) {
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
private fun SecurityLevelBadge(securityLevel: String) {
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
private fun Nip55SettingsCard(
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
private fun AutoStartCard(enabled: Boolean, onToggle: (Boolean) -> Unit) {
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
private fun ForegroundServiceCard(enabled: Boolean, onToggle: (Boolean) -> Unit) {
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
