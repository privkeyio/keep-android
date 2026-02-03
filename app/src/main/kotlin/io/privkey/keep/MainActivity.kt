package io.privkey.keep

import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import io.privkey.keep.nip46.BunkerScreen
import io.privkey.keep.nip46.BunkerService
import io.privkey.keep.nip55.AppPermissionsScreen
import io.privkey.keep.nip55.ConnectedAppsScreen
import io.privkey.keep.nip55.PermissionStore
import io.privkey.keep.nip55.PermissionsManagementScreen
import io.privkey.keep.nip55.SignPolicyScreen
import io.privkey.keep.nip55.SigningHistoryScreen
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.AutoStartStore
import io.privkey.keep.storage.BunkerConfigStore
import io.privkey.keep.storage.ForegroundServiceStore
import io.privkey.keep.storage.KillSwitchStore
import io.privkey.keep.storage.PinStore
import io.privkey.keep.storage.RelayConfigStore
import io.privkey.keep.storage.SignPolicyStore
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.BunkerStatus
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.PeerInfo
import io.privkey.keep.uniffi.ShareInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
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
        val bunkerConfigStore = app.getBunkerConfigStore()

        val allDependenciesAvailable = keepMobile != null &&
            storage != null &&
            relayConfigStore != null &&
            killSwitchStore != null &&
            signPolicyStore != null &&
            autoStartStore != null &&
            foregroundServiceStore != null &&
            pinStore != null &&
            permissionStore != null &&
            bunkerConfigStore != null

        setContent {
            var isPinUnlocked by remember {
                mutableStateOf(pinStore?.isSessionValid() ?: true)
            }

            DisposableEffect(pinStore) {
                val observer = androidx.lifecycle.LifecycleEventObserver { _, event ->
                    if (event == Lifecycle.Event.ON_RESUME) {
                        isPinUnlocked = pinStore?.isSessionValid() ?: true
                    }
                }
                lifecycle.addObserver(observer)
                onDispose {
                    lifecycle.removeObserver(observer)
                }
            }

            KeepAndroidTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val requiresPin = pinStore != null && pinStore.isPinEnabled() && !isPinUnlocked

                    if (requiresPin) {
                        PinUnlockScreen(
                            pinStore = pinStore!!,
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
                            bunkerConfigStore = bunkerConfigStore!!,
                            connectionStateFlow = app.connectionState,
                            securityLevel = storage.getSecurityLevel(),
                            lifecycleOwner = this@MainActivity,
                            onRelaysChanged = { relays ->
                                app.initializeWithRelays(relays) {}
                            },
                            onConnect = { cipher, onResult ->
                                app.connectWithCipher(
                                    cipher,
                                    onSuccess = { onResult(true, null) },
                                    onError = { error -> onResult(false, error) }
                                )
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
                            },
                            onBunkerServiceChanged = { enabled ->
                                app.updateBunkerService(enabled)
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
    bunkerConfigStore: BunkerConfigStore,
    connectionStateFlow: StateFlow<ConnectionState>,
    securityLevel: String,
    lifecycleOwner: LifecycleOwner,
    onRelaysChanged: (List<String>) -> Unit,
    onConnect: (Cipher, (Boolean, String?) -> Unit) -> Unit,
    onBiometricRequest: (String, String, Cipher, (Cipher?) -> Unit) -> Unit,
    onBiometricAuth: (suspend () -> Boolean)? = null,
    onAutoStartChanged: (Boolean) -> Unit = {},
    onForegroundServiceChanged: (Boolean) -> Unit = {},
    onBunkerServiceChanged: (Boolean) -> Unit = {}
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
    val connectionState by connectionStateFlow.collectAsState()
    val isConnected = connectionState.isConnected
    val isConnecting = connectionState.isConnecting
    val connectionError = connectionState.error
    var foregroundServiceEnabled by remember { mutableStateOf(foregroundServiceStore.isEnabled()) }
    var showKillSwitchConfirmDialog by remember { mutableStateOf(false) }
    var showConnectedApps by remember { mutableStateOf(false) }
    var selectedAppPackage by remember { mutableStateOf<String?>(null) }
    var showPinSetup by remember { mutableStateOf(false) }
    var pinEnabled by remember { mutableStateOf(pinStore.isPinEnabled()) }
    var showBunkerScreen by remember { mutableStateOf(false) }
    val bunkerUrl by BunkerService.bunkerUrl.collectAsState()
    val bunkerStatus by BunkerService.status.collectAsState()

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

    if (showBunkerScreen) {
        BunkerScreen(
            bunkerConfigStore = bunkerConfigStore,
            bunkerUrl = bunkerUrl,
            bunkerStatus = bunkerStatus,
            onToggleBunker = onBunkerServiceChanged,
            onDismiss = { showBunkerScreen = false }
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
                    val importId = java.util.UUID.randomUUID().toString()
                    storage.setPendingCipher(importId, cipher)
                    try {
                        val result = withContext(Dispatchers.IO) {
                            storage.setRequestIdContext(importId)
                            try {
                                keepMobile.importShare(data, passphrase, name)
                            } finally {
                                storage.clearRequestIdContext()
                            }
                        }
                        importState = ImportState.Success(result.name)
                        hasShare = keepMobile.hasShare()
                        shareInfo = keepMobile.getShareInfo()
                    } catch (e: Exception) {
                        Log.e("MainActivity", "Import failed: ${e::class.simpleName}")
                        importState = ImportState.Error("Import failed. Please try again.")
                    } finally {
                        storage.clearPendingCipher(importId)
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
            .statusBarsPadding()
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

            ConnectCard(
                isConnected = isConnected,
                isConnecting = isConnecting,
                error = connectionError,
                relaysConfigured = relays.isNotEmpty(),
                onConnect = {
                    val activeKey = storage.getActiveShareKey()
                    val cipher = runCatching {
                        if (activeKey != null) storage.getCipherForShareDecryption(activeKey)
                        else storage.getCipherForDecryption()
                    }.onFailure {
                        Log.e("MainActivity", "Failed to get cipher for connection", it)
                    }.getOrNull() ?: return@ConnectCard

                    onBiometricRequest("Connect to Relays", "Authenticate to connect", cipher) { authedCipher ->
                        authedCipher?.let { onConnect(it) { _, _ -> } }
                    }
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

            Spacer(modifier = Modifier.height(16.dp))

            BunkerCard(
                status = bunkerStatus,
                onClick = { showBunkerScreen = true }
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
            onDisablePin = { currentPin ->
                val disabled = pinStore.disablePin(currentPin)
                if (disabled) pinEnabled = false
                disabled
            }
        )
    }
}
