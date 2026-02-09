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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import io.privkey.keep.navigation.Route
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
import io.privkey.keep.storage.BiometricTimeoutStore
import io.privkey.keep.storage.BunkerConfigStore
import io.privkey.keep.storage.ForegroundServiceStore
import io.privkey.keep.storage.KillSwitchStore
import io.privkey.keep.storage.PinStore
import io.privkey.keep.storage.ProxyConfigStore
import io.privkey.keep.storage.RelayConfigStore
import io.privkey.keep.storage.SignPolicyStore
import io.privkey.keep.ui.theme.KeepAndroidTheme
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
    private var biometricHelper: BiometricHelper? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val app = application as KeepMobileApp
        biometricHelper = BiometricHelper(this, app.getBiometricTimeoutStore())
        val keepMobile = app.getKeepMobile()
        val storage = app.getStorage()
        val relayConfigStore = app.getRelayConfigStore()
        val killSwitchStore = app.getKillSwitchStore()
        val signPolicyStore = app.getSignPolicyStore()
        val autoStartStore = app.getAutoStartStore()
        val foregroundServiceStore = app.getForegroundServiceStore()
        val pinStore = app.getPinStore()
        val biometricTimeoutStore = app.getBiometricTimeoutStore()
        val permissionStore = app.getPermissionStore()
        val bunkerConfigStore = app.getBunkerConfigStore()
        val proxyConfigStore = app.getProxyConfigStore()

        val allDependenciesAvailable = listOf(
            keepMobile, storage, relayConfigStore, killSwitchStore, signPolicyStore,
            autoStartStore, foregroundServiceStore, pinStore, biometricTimeoutStore,
            permissionStore, bunkerConfigStore, proxyConfigStore
        ).all { it != null }

        setContent {
            var isPinUnlocked by remember {
                mutableStateOf(pinStore?.isSessionValid() ?: true)
            }

            val biometricAvailable = biometricHelper?.checkBiometricStatus() ==
                BiometricHelper.BiometricStatus.AVAILABLE

            var isBiometricUnlocked by remember {
                mutableStateOf(
                    biometricTimeoutStore?.isLockOnLaunchEnabled() != true || !biometricAvailable
                )
            }

            DisposableEffect(pinStore) {
                val observer = LifecycleEventObserver { _, event ->
                    if (event == Lifecycle.Event.ON_RESUME) {
                        isPinUnlocked = pinStore?.isSessionValid() ?: true
                    }
                }
                lifecycle.addObserver(observer)
                onDispose { lifecycle.removeObserver(observer) }
            }

            KeepAndroidTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val requiresPin = pinStore != null && pinStore.isPinEnabled() && !isPinUnlocked
                    val requiresBiometric = !isBiometricUnlocked

                    if (requiresPin) {
                        PinUnlockScreen(
                            pinStore = pinStore!!,
                            onUnlocked = { isPinUnlocked = true },
                            onBiometricAuth = if (biometricAvailable) {
                                {
                                    biometricHelper?.authenticate(
                                        title = "Unlock Keep",
                                        subtitle = "Authenticate to open app"
                                    ) ?: false
                                }
                            } else null,
                            onBiometricSuccess = { isBiometricUnlocked = true }
                        )
                    } else if (requiresBiometric) {
                        BiometricUnlockScreen(
                            onAuthenticate = {
                                biometricHelper?.authenticate(
                                    title = "Unlock Keep",
                                    subtitle = "Authenticate to open app",
                                    forcePrompt = true
                                ) ?: false
                            },
                            onUnlocked = { isBiometricUnlocked = true }
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
                            biometricTimeoutStore = biometricTimeoutStore!!,
                            permissionStore = permissionStore!!,
                            bunkerConfigStore = bunkerConfigStore!!,
                            proxyConfigStore = proxyConfigStore!!,
                            connectionStateFlow = app.connectionState,
                            securityLevel = storage.getSecurityLevel(),
                            lifecycleOwner = this@MainActivity,
                            biometricAvailable = biometricAvailable,
                            onRelaysChanged = { relays ->
                                lifecycleScope.launch { app.initializeWithRelays(relays) }
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
                                        val authedCipher = biometricHelper?.authenticateWithCrypto(
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
                                biometricHelper?.authenticate(
                                    title = "Disable Kill Switch",
                                    subtitle = "Authenticate to re-enable signing"
                                ) ?: false
                            },
                            onAutoStartChanged = { enabled ->
                                app.updateNetworkMonitoring(enabled)
                            },
                            onForegroundServiceChanged = { enabled ->
                                app.updateForegroundService(enabled)
                            },
                            onBunkerServiceChanged = { enabled ->
                                app.updateBunkerService(enabled)
                            },
                            onReconnectRelays = { app.reconnectRelays() },
                            onClearCertificatePin = app::clearCertificatePin,
                            onClearAllCertificatePins = app::clearAllCertificatePins,
                            onDismissPinMismatch = app::dismissPinMismatch,
                            onAccountSwitched = { app.onAccountSwitched() }
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
    biometricTimeoutStore: BiometricTimeoutStore,
    permissionStore: PermissionStore,
    bunkerConfigStore: BunkerConfigStore,
    proxyConfigStore: ProxyConfigStore,
    connectionStateFlow: StateFlow<ConnectionState>,
    securityLevel: String,
    lifecycleOwner: LifecycleOwner,
    onRelaysChanged: (List<String>) -> Unit,
    onConnect: (Cipher, (Boolean, String?) -> Unit) -> Unit,
    onBiometricRequest: (String, String, Cipher, (Cipher?) -> Unit) -> Unit,
    biometricAvailable: Boolean = false,
    onBiometricAuth: (suspend () -> Boolean)? = null,
    onAutoStartChanged: (Boolean) -> Unit = {},
    onForegroundServiceChanged: (Boolean) -> Unit = {},
    onBunkerServiceChanged: (Boolean) -> Unit = {},
    onReconnectRelays: () -> Unit = {},
    onClearCertificatePin: (String) -> Unit = {},
    onClearAllCertificatePins: () -> Unit = {},
    onDismissPinMismatch: () -> Unit = {},
    onAccountSwitched: suspend () -> Unit = {}
) {
    val appContext = LocalContext.current.applicationContext
    var hasShare by remember { mutableStateOf(keepMobile.hasShare()) }
    var shareInfo by remember { mutableStateOf(keepMobile.getShareInfo()) }
    var peers by remember { mutableStateOf<List<PeerInfo>>(emptyList()) }
    var pendingCount by remember { mutableStateOf(0) }
    var allAccounts by remember { mutableStateOf<List<AccountInfo>>(emptyList()) }
    var activeAccountKey by remember { mutableStateOf<String?>(null) }
    var showAccountSwitcher by remember { mutableStateOf(false) }
    var showImportScreen by remember { mutableStateOf(false) }
    var showImportNsecScreen by remember { mutableStateOf(false) }
    var showShareDetails by remember { mutableStateOf(false) }
    var showExportScreen by remember { mutableStateOf(false) }
    var showPermissionsScreen by remember { mutableStateOf(false) }
    var showHistoryScreen by remember { mutableStateOf(false) }
    var showSignPolicyScreen by remember { mutableStateOf(false) }
    var importState by remember { mutableStateOf<ImportState>(ImportState.Idle) }
    val coroutineScope = rememberCoroutineScope()
    var relays by remember { mutableStateOf<List<String>>(emptyList()) }
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
    var biometricTimeout by remember { mutableStateOf(biometricTimeoutStore.getTimeout()) }
    var biometricLockOnLaunch by remember { mutableStateOf(biometricTimeoutStore.isLockOnLaunchEnabled()) }
    var showBunkerScreen by remember { mutableStateOf(false) }
    val bunkerUrl by BunkerService.bunkerUrl.collectAsState()
    val bunkerStatus by BunkerService.status.collectAsState()
    var proxyEnabled by remember { mutableStateOf(proxyConfigStore.isEnabled()) }
    var proxyHost by remember { mutableStateOf(proxyConfigStore.getHost()) }
    var proxyPort by remember { mutableStateOf(proxyConfigStore.getPort()) }
    var certificatePins by remember { mutableStateOf(keepMobile.getCertificatePinsCompat()) }
    var showSecuritySettings by remember { mutableStateOf(false) }

    val handleKillSwitchToggle: (Boolean) -> Unit = { newValue ->
        if (newValue) {
            showKillSwitchConfirmDialog = true
        } else {
            coroutineScope.launch {
                val authenticated = onBiometricAuth?.invoke() ?: false
                if (authenticated) {
                    withContext(Dispatchers.IO) { killSwitchStore.setEnabled(false) }
                    killSwitchEnabled = false
                }
            }
        }
    }

    val accountActions = remember {
        AccountActions(
            keepMobile = keepMobile,
            storage = storage,
            relayConfigStore = relayConfigStore,
            coroutineScope = coroutineScope,
            appContext = appContext,
            onBiometricRequest = onBiometricRequest,
            onAccountSwitched = onAccountSwitched,
            onStateChanged = { state ->
                hasShare = state.hasShare
                shareInfo = state.shareInfo
                activeAccountKey = state.activeAccountKey
                allAccounts = state.allAccounts
                relays = state.relays
            }
        )
    }

    LaunchedEffect(relays) {
        accountActions.setCurrentRelays(relays)
    }

    suspend fun refreshCertificatePins() {
        certificatePins = withContext(Dispatchers.IO) { keepMobile.getCertificatePinsCompat() }
    }

    LaunchedEffect(Unit) {
        val initial = withContext(Dispatchers.IO) {
            val a = storage.listAllShares().map { it.toAccountInfo() }
            val k = storage.getActiveShareKey()
            val r = if (k != null) relayConfigStore.getRelaysForAccount(k) else relayConfigStore.getRelays()
            Triple(a, k, r)
        }
        allAccounts = initial.first
        activeAccountKey = initial.second
        relays = initial.third
    }

    LaunchedEffect(Unit) {
        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                val (newHasShare, newShareInfo, newAccounts, newActiveKey, newPeers, newPendingCount) = withContext(Dispatchers.IO) {
                    val h = keepMobile.hasShare()
                    val s = keepMobile.getShareInfo()
                    val a = storage.listAllShares().map { it.toAccountInfo() }
                    val k = storage.getActiveShareKey()
                    val p = if (h) keepMobile.getPeers() else emptyList()
                    val pc = if (h) keepMobile.getPendingRequests().size else 0
                    PollResult(h, s, a, k, p, pc)
                }
                hasShare = newHasShare
                shareInfo = newShareInfo
                allAccounts = newAccounts
                activeAccountKey = newActiveKey
                peers = newPeers
                pendingCount = newPendingCount
                refreshCertificatePins()
                delay(10_000)
            }
        }
    }

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

    if (showSecuritySettings) {
        SecuritySettingsScreen(
            pinEnabled = pinEnabled,
            onSetupPin = { showPinSetup = true },
            onDisablePin = { currentPin ->
                val disabled = pinStore.disablePin(currentPin)
                if (disabled) pinEnabled = false
                disabled
            },
            biometricTimeout = biometricTimeout,
            onTimeoutChanged = { newTimeout ->
                coroutineScope.launch {
                    val saved = withContext(Dispatchers.IO) { biometricTimeoutStore.setTimeout(newTimeout) }
                    if (saved) biometricTimeout = newTimeout
                }
            },
            biometricLockOnLaunch = biometricLockOnLaunch,
            onBiometricLockOnLaunchChanged = { enabled ->
                coroutineScope.launch {
                    val saved = withContext(Dispatchers.IO) { biometricTimeoutStore.setLockOnLaunch(enabled) }
                    if (saved) biometricLockOnLaunch = enabled
                }
            },
            biometricAvailable = biometricAvailable,
            killSwitchEnabled = killSwitchEnabled,
            onKillSwitchToggle = handleKillSwitchToggle,
            onDismiss = { showSecuritySettings = false }
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

    if (showAccountSwitcher) {
        AccountSwitcherSheet(
            accounts = allAccounts,
            activeAccountKey = activeAccountKey,
            onSwitchAccount = { account ->
                accountActions.switchAccount(account) { showAccountSwitcher = false }
            },
            onDeleteAccount = { account ->
                accountActions.deleteAccount(account) { showAccountSwitcher = false }
            },
            onImportAccount = {
                showAccountSwitcher = false
                showImportScreen = true
            },
            onImportNsec = {
                showAccountSwitcher = false
                showImportNsecScreen = true
            },
            onDismiss = { showAccountSwitcher = false }
        )
    }

    if (showImportScreen) {
        ImportShareScreen(
            onImport = { data, passphrase, name, cipher ->
                accountActions.importShare(data, passphrase, name, cipher) { importState = it }
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

    if (showImportNsecScreen) {
        ImportNsecScreen(
            onImport = { nsec, name, cipher ->
                accountActions.importNsec(nsec, name, cipher) { importState = it }
            },
            onGetCipher = { storage.getCipherForEncryption() },
            onBiometricAuth = { cipher, callback ->
                onBiometricRequest("Import nsec", "Authenticate to store key securely", cipher, callback)
            },
            onDismiss = {
                showImportNsecScreen = false
                importState = ImportState.Idle
            },
            importState = importState
        )
        return
    }

    val pinMismatch = connectionState.pinMismatch
    if (pinMismatch != null) {
        AlertDialog(
            onDismissRequest = onDismissPinMismatch,
            title = { Text("Certificate Pin Mismatch") },
            text = {
                Text("The certificate for ${pinMismatch.hostname} has changed. This could indicate a security issue or a legitimate certificate rotation.")
            },
            confirmButton = {
                TextButton(onClick = {
                    coroutineScope.launch {
                        withContext(Dispatchers.IO) { onClearCertificatePin(pinMismatch.hostname) }
                        refreshCertificatePins()
                        onReconnectRelays()
                    }
                }) {
                    Text("Clear Pin & Retry")
                }
            },
            dismissButton = {
                TextButton(onClick = onDismissPinMismatch) {
                    Text("Dismiss")
                }
            }
        )
    }

    val navController = rememberNavController()

    Scaffold(
        bottomBar = {
            NavigationBar {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentDestination = navBackStackEntry?.destination
                Route.items.forEach { route ->
                    NavigationBarItem(
                        icon = { Icon(route.icon, contentDescription = route.label) },
                        label = { Text(route.label) },
                        selected = currentDestination?.hierarchy?.any { it.route == route.route } == true,
                        onClick = {
                            navController.navigate(route.route) {
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        }
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Route.Home.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Route.Home.route) {
                HomeTab(
                    hasShare = hasShare,
                    shareInfo = shareInfo,
                    allAccounts = allAccounts,
                    peers = peers,
                    pendingCount = pendingCount,
                    isConnected = isConnected,
                    isConnecting = isConnecting,
                    connectionError = connectionError,
                    relays = relays,
                    securityLevel = securityLevel,
                    killSwitchEnabled = killSwitchEnabled,
                    onShareDetailsClick = { showShareDetails = true },
                    onAccountSwitcherClick = { showAccountSwitcher = true },
                    onImport = { showImportScreen = true },
                    onImportNsec = { showImportNsecScreen = true },
                    onConnect = {
                        coroutineScope.launch {
                            val cipher = withContext(Dispatchers.IO) {
                                val key = storage.getActiveShareKey()
                                runCatching {
                                    if (key != null) storage.getCipherForShareDecryption(key)
                                    else storage.getCipherForDecryption()
                                }.onFailure {
                                    if (BuildConfig.DEBUG) Log.e("MainActivity", "Failed to get cipher for connection", it)
                                }.getOrNull()
                            }
                            if (cipher == null) return@launch
                            onBiometricRequest("Connect to Relays", "Authenticate to connect", cipher) { authedCipher ->
                                authedCipher?.let { onConnect(it) { _, _ -> } }
                            }
                        }
                    },
                    onKillSwitchToggle = handleKillSwitchToggle
                )
            }

            composable(Route.Apps.route) {
                AppsTab(
                    hasShare = hasShare,
                    bunkerStatus = bunkerStatus,
                    onConnectedAppsClick = { showConnectedApps = true },
                    onSignPolicyClick = { showSignPolicyScreen = true },
                    onPermissionsClick = { showPermissionsScreen = true },
                    onHistoryClick = { showHistoryScreen = true },
                    onBunkerClick = { showBunkerScreen = true }
                )
            }

            composable(Route.Settings.route) {
                SettingsTab(
                    hasShare = hasShare,
                    relays = relays,
                    certificatePins = certificatePins,
                    proxyEnabled = proxyEnabled,
                    proxyHost = proxyHost,
                    proxyPort = proxyPort,
                    autoStartEnabled = autoStartEnabled,
                    foregroundServiceEnabled = foregroundServiceEnabled,
                    isConnected = isConnected,
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
                    },
                    onClearPin = { hostname ->
                        coroutineScope.launch {
                            withContext(Dispatchers.IO) { onClearCertificatePin(hostname) }
                            refreshCertificatePins()
                        }
                    },
                    onClearAllPins = {
                        coroutineScope.launch {
                            withContext(Dispatchers.IO) { onClearAllCertificatePins() }
                            refreshCertificatePins()
                        }
                    },
                    onProxyToggle = { enabled ->
                        coroutineScope.launch {
                            withContext(Dispatchers.IO) { proxyConfigStore.setEnabled(enabled) }
                            proxyEnabled = enabled
                            if (isConnected) onReconnectRelays()
                        }
                    },
                    onProxyConfigChange = { host, port ->
                        coroutineScope.launch {
                            val saved = withContext(Dispatchers.IO) { proxyConfigStore.setProxyConfig(host, port) }
                            if (saved) {
                                proxyHost = host
                                proxyPort = port
                                if (proxyEnabled && isConnected) onReconnectRelays()
                            }
                        }
                    },
                    onAutoStartToggle = { newValue ->
                        coroutineScope.launch {
                            withContext(Dispatchers.IO) { autoStartStore.setEnabled(newValue) }
                            autoStartEnabled = newValue
                            onAutoStartChanged(newValue)
                        }
                    },
                    onForegroundServiceToggle = { newValue ->
                        coroutineScope.launch {
                            withContext(Dispatchers.IO) { foregroundServiceStore.setEnabled(newValue) }
                            foregroundServiceEnabled = newValue
                            onForegroundServiceChanged(newValue)
                        }
                    },
                    onSecurityClick = { showSecuritySettings = true }
                )
            }

            composable(Route.Account.route) {
                AccountTab(
                    hasShare = hasShare,
                    shareInfo = shareInfo,
                    allAccounts = allAccounts,
                    onAccountSwitcherClick = { showAccountSwitcher = true },
                    onShareDetailsClick = { showShareDetails = true },
                    onExportClick = { showExportScreen = true },
                    onImport = { showImportScreen = true },
                    onImportNsec = { showImportNsecScreen = true }
                )
            }
        }
    }
}

@Composable
private fun HomeTab(
    hasShare: Boolean,
    shareInfo: ShareInfo?,
    allAccounts: List<AccountInfo>,
    peers: List<PeerInfo>,
    pendingCount: Int,
    isConnected: Boolean,
    isConnecting: Boolean,
    connectionError: String?,
    relays: List<String>,
    securityLevel: String,
    killSwitchEnabled: Boolean,
    onShareDetailsClick: () -> Unit,
    onAccountSwitcherClick: () -> Unit,
    onImport: () -> Unit,
    onImportNsec: () -> Unit,
    onConnect: () -> Unit,
    onKillSwitchToggle: (Boolean) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(text = "Keep", style = MaterialTheme.typography.headlineLarge)
        Spacer(modifier = Modifier.height(4.dp))
        SecurityLevelBadge(securityLevel)
        Spacer(modifier = Modifier.height(16.dp))

        KillSwitchCard(
            enabled = killSwitchEnabled,
            onToggle = onKillSwitchToggle
        )

        Spacer(modifier = Modifier.height(16.dp))

        if (allAccounts.isNotEmpty()) {
            AccountSelectorCard(
                accountCount = allAccounts.size,
                onClick = onAccountSwitcherClick
            )
            Spacer(modifier = Modifier.height(16.dp))
        }

        val currentShareInfo = shareInfo
        if (hasShare && currentShareInfo != null) {
            ShareInfoCard(
                info = currentShareInfo,
                onClick = onShareDetailsClick
            )
            Spacer(modifier = Modifier.height(16.dp))

            ConnectCard(
                isConnected = isConnected,
                isConnecting = isConnecting,
                error = connectionError,
                relaysConfigured = relays.isNotEmpty(),
                onConnect = onConnect
            )
            Spacer(modifier = Modifier.height(16.dp))

            PeersCard(peers)

            if (pendingCount > 0) {
                Spacer(modifier = Modifier.height(16.dp))
                Badge { Text("$pendingCount pending") }
            }
        } else {
            NoShareCard(
                onImport = onImport,
                onImportNsec = onImportNsec
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
private fun AppsTab(
    hasShare: Boolean,
    bunkerStatus: io.privkey.keep.uniffi.BunkerStatus,
    onConnectedAppsClick: () -> Unit,
    onSignPolicyClick: () -> Unit,
    onPermissionsClick: () -> Unit,
    onHistoryClick: () -> Unit,
    onBunkerClick: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(text = "Apps", style = MaterialTheme.typography.headlineLarge)
        Spacer(modifier = Modifier.height(16.dp))

        if (hasShare) {
            ConnectedAppsCard(onClick = onConnectedAppsClick)
            Spacer(modifier = Modifier.height(16.dp))

            Nip55SettingsCard(
                onSignPolicyClick = onSignPolicyClick,
                onPermissionsClick = onPermissionsClick,
                onHistoryClick = onHistoryClick
            )
            Spacer(modifier = Modifier.height(16.dp))

            BunkerCard(
                status = bunkerStatus,
                onClick = onBunkerClick
            )
        } else {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        "Import a key to manage connected apps",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
private fun SettingsTab(
    hasShare: Boolean,
    relays: List<String>,
    certificatePins: List<CertificatePin>,
    proxyEnabled: Boolean,
    proxyHost: String,
    proxyPort: Int,
    autoStartEnabled: Boolean,
    foregroundServiceEnabled: Boolean,
    isConnected: Boolean,
    onAddRelay: (String) -> Unit,
    onRemoveRelay: (String) -> Unit,
    onClearPin: (String) -> Unit,
    onClearAllPins: () -> Unit,
    onProxyToggle: (Boolean) -> Unit,
    onProxyConfigChange: (String, Int) -> Unit,
    onAutoStartToggle: (Boolean) -> Unit,
    onForegroundServiceToggle: (Boolean) -> Unit,
    onSecurityClick: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(text = "Settings", style = MaterialTheme.typography.headlineLarge)
        Spacer(modifier = Modifier.height(16.dp))

        if (hasShare) {
            RelaysCard(
                relays = relays,
                onAddRelay = onAddRelay,
                onRemoveRelay = onRemoveRelay
            )
            Spacer(modifier = Modifier.height(16.dp))

            CertificatePinsCard(
                pins = certificatePins,
                onClearPin = onClearPin,
                onClearAllPins = onClearAllPins
            )
            Spacer(modifier = Modifier.height(16.dp))

            ProxySettingsCard(
                enabled = proxyEnabled,
                host = proxyHost,
                port = proxyPort,
                onToggle = onProxyToggle,
                onConfigChange = onProxyConfigChange
            )
            Spacer(modifier = Modifier.height(16.dp))
        }

        AutoStartCard(
            enabled = autoStartEnabled,
            onToggle = onAutoStartToggle
        )
        Spacer(modifier = Modifier.height(16.dp))

        ForegroundServiceCard(
            enabled = foregroundServiceEnabled,
            onToggle = onForegroundServiceToggle
        )
        Spacer(modifier = Modifier.height(16.dp))

        SecuritySettingsCard(onClick = onSecurityClick)

        Spacer(modifier = Modifier.height(16.dp))
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SecuritySettingsCard(onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth(), onClick = onClick) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Security", style = MaterialTheme.typography.titleMedium)
                Text(
                    "PIN, biometrics, kill switch",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text("Manage", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        }
    }
}

@Composable
private fun AccountTab(
    hasShare: Boolean,
    shareInfo: ShareInfo?,
    allAccounts: List<AccountInfo>,
    onAccountSwitcherClick: () -> Unit,
    onShareDetailsClick: () -> Unit,
    onExportClick: () -> Unit,
    onImport: () -> Unit,
    onImportNsec: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(text = "Account", style = MaterialTheme.typography.headlineLarge)
        Spacer(modifier = Modifier.height(16.dp))

        if (allAccounts.isNotEmpty()) {
            AccountSelectorCard(
                accountCount = allAccounts.size,
                onClick = onAccountSwitcherClick
            )
            Spacer(modifier = Modifier.height(16.dp))
        }

        val currentShareInfo = shareInfo
        if (hasShare && currentShareInfo != null) {
            ShareInfoCard(
                info = currentShareInfo,
                onClick = onShareDetailsClick
            )
            Spacer(modifier = Modifier.height(16.dp))

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Key Management", style = MaterialTheme.typography.titleMedium)
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedButton(
                        onClick = onExportClick,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Export Share")
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = onImport,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Import Share")
                        }
                        OutlinedButton(
                            onClick = onImportNsec,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Import nsec")
                        }
                    }
                }
            }
        } else {
            NoShareCard(
                onImport = onImport,
                onImportNsec = onImportNsec
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

private data class PollResult(
    val hasShare: Boolean,
    val shareInfo: ShareInfo?,
    val allAccounts: List<AccountInfo>,
    val activeAccountKey: String?,
    val peers: List<PeerInfo>,
    val pendingCount: Int
)
