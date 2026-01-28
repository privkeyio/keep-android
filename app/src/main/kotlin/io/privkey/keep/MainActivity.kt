package io.privkey.keep

import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
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
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.KillSwitchStore
import io.privkey.keep.storage.RelayConfigStore
import io.privkey.keep.ui.theme.KeepAndroidTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.PeerInfo
import io.privkey.keep.uniffi.ShareInfo
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

        setContent {
            KeepAndroidTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    if (keepMobile != null && storage != null && relayConfigStore != null && killSwitchStore != null) {
                        MainScreen(
                            keepMobile = keepMobile,
                            storage = storage,
                            relayConfigStore = relayConfigStore,
                            killSwitchStore = killSwitchStore,
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
    securityLevel: String,
    lifecycleOwner: LifecycleOwner,
    onRelaysChanged: (List<String>) -> Unit,
    onBiometricRequest: (String, String, Cipher, (Cipher?) -> Unit) -> Unit,
    onBiometricAuth: (suspend () -> Boolean)? = null
) {
    var hasShare by remember { mutableStateOf(keepMobile.hasShare()) }
    var shareInfo by remember { mutableStateOf(keepMobile.getShareInfo()) }
    var peers by remember { mutableStateOf<List<PeerInfo>>(emptyList()) }
    var pendingCount by remember { mutableStateOf(0) }
    var showImportScreen by remember { mutableStateOf(false) }
    var importState by remember { mutableStateOf<ImportState>(ImportState.Idle) }
    val coroutineScope = rememberCoroutineScope()
    var relays by remember { mutableStateOf(relayConfigStore.getRelays()) }
    var killSwitchEnabled by remember { mutableStateOf(killSwitchStore.isEnabled()) }
    var showKillSwitchConfirmDialog by remember { mutableStateOf(false) }

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
            .padding(16.dp),
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
                            killSwitchStore.setEnabled(false)
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
                        killSwitchStore.setEnabled(true)
                        killSwitchEnabled = true
                        showKillSwitchConfirmDialog = false
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
            ShareInfoCard(currentShareInfo)

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

            PeersCard(peers)

            if (pendingCount > 0) {
                Spacer(modifier = Modifier.height(16.dp))
                Badge { Text("$pendingCount pending") }
            }
        } else {
            NoShareCard(
                onImport = { showImportScreen = true }
            )
        }
    }
}

@Composable
private fun ShareInfoCard(info: ShareInfo) {
    Card(modifier = Modifier.fillMaxWidth()) {
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
    val statusColor = if (peer.status.name == "Online") {
        MaterialTheme.colorScheme.primary
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant
    }

    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text("Share ${peer.shareIndex}")
        Text(peer.status.name, color = statusColor)
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
private fun KillSwitchCard(
    enabled: Boolean,
    onToggle: (Boolean) -> Unit
) {
    val containerColor = if (enabled) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surfaceVariant
    val contentColor = if (enabled) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurfaceVariant

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
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
                    checkedThumbColor = MaterialTheme.colorScheme.error,
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
