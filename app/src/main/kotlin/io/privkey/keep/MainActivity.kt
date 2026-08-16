package io.privkey.keep

import android.content.Context
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withLink
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
import io.privkey.keep.descriptor.DescriptorSessionManager
import io.privkey.keep.descriptor.WalletDescriptorScreen
import io.privkey.keep.navigation.Route
import io.privkey.keep.nip46.BunkerScreen
import io.privkey.keep.nip46.BunkerService
import io.privkey.keep.nip55.AUDIT_OP_ACCOUNT_DELETE
import io.privkey.keep.nip55.AppPermissionsScreen
import io.privkey.keep.nip55.ConnectedAppsScreen
import io.privkey.keep.nip55.EventLogScreen
import io.privkey.keep.ui.components.KeepCard
import io.privkey.keep.ui.components.KeepListRow
import io.privkey.keep.ui.components.KeepRowAction
import io.privkey.keep.nip55.PermissionStore
import io.privkey.keep.nip55.PermissionsManagementScreen
import io.privkey.keep.nip55.RelayAuthWhitelistScreen
import io.privkey.keep.nip55.SignPolicyScreen
import io.privkey.keep.nip55.SigningHistoryScreen
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.AutoStartStore
import io.privkey.keep.storage.BiometricTimeoutStore
import io.privkey.keep.storage.ForegroundServiceStore
import io.privkey.keep.storage.PinStore
import io.privkey.keep.storage.toSelection
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.crypto.Cipher

private const val MAX_SEED_WORDS_LENGTH = 1024

class MainActivity : FragmentActivity() {
    private var biometricHelper: BiometricHelper? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val app = application as? KeepMobileApp ?: run { finish(); return }
        biometricHelper = BiometricHelper(this, app.getBiometricTimeoutStore())
        val keepMobile = app.getKeepMobile()
        val storage = app.getStorage()
        val signPolicyStore = app.getSignPolicyStore()
        val autoStartStore = app.getAutoStartStore()
        val foregroundServiceStore = app.getForegroundServiceStore()
        val pinStore = app.getPinStore()
        val biometricTimeoutStore = app.getBiometricTimeoutStore()
        val permissionStore = app.getPermissionStore()
        val onboardingStore = app.getOnboardingStore()

        val allDependenciesAvailable = listOf(
            keepMobile, storage, signPolicyStore,
            autoStartStore, foregroundServiceStore, pinStore, biometricTimeoutStore,
            permissionStore, onboardingStore
        ).all { it != null }

        setContent {
            val onboardingScope = rememberCoroutineScope()

            var isPinUnlocked by remember {
                mutableStateOf(pinStore?.isSessionValid() ?: true)
            }

            var onboardingCompleted by remember {
                mutableStateOf(onboardingStore?.isCompleted() ?: true)
            }

            var biometricStatus by remember {
                mutableStateOf(
                    biometricHelper?.checkBiometricStatus()
                        ?: BiometricHelper.BiometricStatus.NOT_AVAILABLE
                )
            }
            val biometricAvailable = biometricStatus == BiometricHelper.BiometricStatus.AVAILABLE

            var isBiometricUnlocked by remember {
                val lockOnLaunch = biometricAvailable &&
                    biometricTimeoutStore?.isLockOnLaunchEnabled() == true
                mutableStateOf(!lockOnLaunch)
            }

            DisposableEffect(pinStore) {
                val observer = LifecycleEventObserver { _, event ->
                    if (event == Lifecycle.Event.ON_RESUME) {
                        isPinUnlocked = pinStore?.isSessionValid() ?: true
                        biometricStatus = biometricHelper?.checkBiometricStatus()
                            ?: BiometricHelper.BiometricStatus.NOT_AVAILABLE
                        if (biometricAvailable &&
                            biometricTimeoutStore?.isLockOnLaunchEnabled() == true &&
                            biometricTimeoutStore.requiresBiometric()) {
                            isBiometricUnlocked = false
                        }
                    } else if (event == Lifecycle.Event.ON_STOP) {
                        // Close the biometric timeout window when the app leaves the
                        // foreground. Otherwise a recently-authenticated session survives a
                        // background transition, letting someone who resumes the app perform a
                        // presence-gated action (cosign approval, kill-switch disable) without a
                        // fresh biometric. ON_STOP (not ON_PAUSE) so the in-app BiometricPrompt
                        // overlay, which pauses but does not stop the activity, is not clobbered.
                        // Also lets lock-on-launch re-engage on resume (an open window suppressed it).
                        biometricTimeoutStore?.invalidateSession()
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
                    val pinStoreForUnlock = pinStore?.takeIf { it.isPinEnabled() && !isPinUnlocked }

                    val unlockTitle = stringResource(R.string.main_unlock_title)
                    val unlockSubtitle = stringResource(R.string.main_unlock_subtitle)
                    if (pinStoreForUnlock != null) {
                        PinUnlockScreen(
                            pinStore = pinStoreForUnlock,
                            onUnlocked = { isPinUnlocked = true },
                            onBiometricAuth = if (biometricAvailable) {
                                {
                                    biometricHelper?.authenticate(
                                        title = unlockTitle,
                                        subtitle = unlockSubtitle,
                                        forcePrompt = true
                                    ) ?: false
                                }
                            } else null,
                            onBiometricSuccess = { isBiometricUnlocked = true }
                        )
                    } else if (!isBiometricUnlocked) {
                        BiometricUnlockScreen(
                            onAuthenticate = {
                                biometricHelper?.authenticateWithResult(
                                    title = unlockTitle,
                                    subtitle = unlockSubtitle,
                                    forcePrompt = true
                                ) ?: BiometricHelper.AuthResult.FAILED
                            },
                            onUnlocked = { isBiometricUnlocked = true }
                        )
                    } else if (allDependenciesAvailable && !onboardingCompleted) {
                        val safeSignPolicyStore = signPolicyStore ?: return@Surface
                        val safeOnboardingStore = onboardingStore ?: return@Surface
                        OnboardingScreen(
                            signPolicyStore = safeSignPolicyStore,
                            onDone = { policy ->
                                onboardingScope.launch {
                                    withContext(Dispatchers.IO) {
                                        safeSignPolicyStore.setGlobalPolicy(policy.toSelection())
                                        safeOnboardingStore.setCompleted(true)
                                    }
                                    onboardingCompleted = true
                                }
                            }
                        )
                    } else if (allDependenciesAvailable) {
                        val safeKeepMobile = keepMobile ?: return@Surface
                        val safeStorage = storage ?: return@Surface
                        val safeSignPolicyStore = signPolicyStore ?: return@Surface
                        val safeAutoStartStore = autoStartStore ?: return@Surface
                        val safeForegroundServiceStore = foregroundServiceStore ?: return@Surface
                        val safePinStore = pinStore ?: return@Surface
                        val safeBiometricTimeoutStore = biometricTimeoutStore ?: return@Surface
                        val safePermissionStore = permissionStore ?: return@Surface
                        MainScreen(
                            keepMobile = safeKeepMobile,
                            storage = safeStorage,
                            signPolicyStore = safeSignPolicyStore,
                            autoStartStore = safeAutoStartStore,
                            foregroundServiceStore = safeForegroundServiceStore,
                            pinStore = safePinStore,
                            biometricTimeoutStore = safeBiometricTimeoutStore,
                            permissionStore = safePermissionStore,
                            securityLevel = safeStorage.getSecurityLevel(),
                            lifecycleOwner = this@MainActivity,
                            biometricStatus = biometricStatus,
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
                                            getString(R.string.main_auth_failed),
                                            Toast.LENGTH_SHORT
                                        ).show()
                                        callback(null)
                                    }
                                }
                            },
                            onBiometricAuth = { title, subtitle, forcePrompt ->
                                biometricHelper?.authenticate(
                                    title = title,
                                    subtitle = subtitle,
                                    forcePrompt = forcePrompt
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
                            onStageCertificatePin = app::stageCertificatePin,
                            onRemoveCertificatePin = { hostname, spkiHash ->
                                app.removeCertificatePin(hostname, spkiHash)
                            },
                            onDismissPinMismatch = app::dismissPinMismatch,
                            onAccountSwitched = { app.onAccountSwitched() }
                        )
                    } else {
                        ErrorScreen(app.getInitError() ?: stringResource(R.string.main_init_app_failed))
                    }
                }
            }
        }
    }
}

private fun showRelayHostCheckToast(context: Context, result: RelayHostCheck) {
    val resId = when (result) {
        RelayHostCheck.UNRESOLVABLE -> R.string.connections_relays_error_unreachable
        RelayHostCheck.INTERNAL -> R.string.connections_relays_error_private
        RelayHostCheck.REACHABLE -> return
    }
    Toast.makeText(context, resId, Toast.LENGTH_LONG).show()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    keepMobile: KeepMobile,
    storage: AndroidKeystoreStorage,
    signPolicyStore: SignPolicyStore,
    autoStartStore: AutoStartStore,
    foregroundServiceStore: ForegroundServiceStore,
    pinStore: PinStore,
    biometricTimeoutStore: BiometricTimeoutStore,
    permissionStore: PermissionStore,
    securityLevel: String,
    lifecycleOwner: LifecycleOwner,
    onRelaysChanged: (List<String>) -> Unit,
    onConnect: (Cipher, (Boolean, String?) -> Unit) -> Unit,
    onBiometricRequest: (String, String, Cipher, (Cipher?) -> Unit) -> Unit,
    biometricStatus: BiometricHelper.BiometricStatus = BiometricHelper.BiometricStatus.NOT_AVAILABLE,
    onBiometricAuth: (suspend (title: String, subtitle: String, forcePrompt: Boolean) -> Boolean)? = null,
    onAutoStartChanged: (Boolean) -> Unit = {},
    onForegroundServiceChanged: (Boolean) -> Unit = {},
    onBunkerServiceChanged: (Boolean) -> Unit = {},
    onReconnectRelays: () -> Unit = {},
    onClearCertificatePin: (String) -> Unit = {},
    onClearAllCertificatePins: () -> Unit = {},
    onStageCertificatePin: (String, String) -> Boolean = { _, _ -> false },
    onRemoveCertificatePin: (String, String) -> CertPinRemoval? = { _, _ -> null },
    onDismissPinMismatch: () -> Unit = {},
    onAccountSwitched: suspend () -> Unit = {}
) {
    val appContext = LocalContext.current.applicationContext
    val biometricAvailable = biometricStatus == BiometricHelper.BiometricStatus.AVAILABLE
    val requireBiometricReady = { BiometricHelper.requireBiometricReady(appContext, biometricStatus) }
    var hasShare by remember { mutableStateOf(keepMobile.hasShare()) }
    var shareInfo by remember { mutableStateOf(keepMobile.getShareInfo()) }
    var allAccounts by remember { mutableStateOf<List<AccountInfo>>(emptyList()) }
    var activeAccountKey by remember { mutableStateOf<String?>(null) }
    var showAccountSwitcher by remember { mutableStateOf(false) }
    var showImportScreen by remember { mutableStateOf(false) }
    var showCreateGroupScreen by remember { mutableStateOf(false) }
    var showImportNsecScreen by remember { mutableStateOf(false) }
    var showShareDetails by remember { mutableStateOf(false) }
    var showExportScreen by remember { mutableStateOf(false) }
    var showExportNcryptsecScreen by remember { mutableStateOf(false) }
    var showPermissionsScreen by remember { mutableStateOf(false) }
    var showHistoryScreen by remember { mutableStateOf(false) }
    var showSignPolicyScreen by remember { mutableStateOf(false) }
    var showRelayAuthWhitelistScreen by remember { mutableStateOf(false) }
    var importState by remember { mutableStateOf<ImportState>(ImportState.Idle) }
    var createGroupState by remember { mutableStateOf<CreateGroupState>(CreateGroupState.Idle) }
    val coroutineScope = rememberCoroutineScope()
    var relays by remember { mutableStateOf<List<String>>(emptyList()) }
    var killSwitchEnabled by remember { mutableStateOf(runCatching { keepMobile.getKillSwitch() }.getOrDefault(true)) }
    var autoStartEnabled by remember { mutableStateOf(autoStartStore.isEnabled()) }

    val appLiveState = (LocalContext.current.applicationContext as? KeepMobileApp)?.liveState
    val signingAuditLog = (LocalContext.current.applicationContext as? KeepMobileApp)?.getSigningAuditLog()
    val eventLogStore = (LocalContext.current.applicationContext as? KeepMobileApp)?.getEventLogStore()
    val peers = appLiveState?.peers ?: emptyList()
    val pendingCount = appLiveState?.pendingRequests?.size ?: 0
    val connectionStatus = appLiveState?.connectionStatus
    val isConnected = connectionStatus is ConnectionStatus.Connected
    val isConnecting = connectionStatus is ConnectionStatus.Connecting
    val connectionError = (connectionStatus as? ConnectionStatus.Error)?.message

    val pinMismatchInfo = (appContext as? KeepMobileApp)?.getPinMismatch()

    var foregroundServiceEnabled by remember { mutableStateOf(foregroundServiceStore.isEnabled()) }
    var showKillSwitchConfirmDialog by remember { mutableStateOf(false) }
    var showKillSwitchPinPrompt by remember { mutableStateOf(false) }
    // Re-auth gate for security-downgrade actions (e.g. clearing/removing a certificate
    // pin, which re-opens trust-on-first-use for that host).
    var pendingAuthGateAction by remember { mutableStateOf<(suspend () -> Unit)?>(null) }
    var authGateTitle by remember { mutableStateOf("") }
    var authGateMessage by remember { mutableStateOf("") }
    var authGateConfirm by remember { mutableStateOf("") }
    var showConnectedApps by remember { mutableStateOf(false) }
    var selectedAppPackage by remember { mutableStateOf<String?>(null) }
    var showPinSetup by remember { mutableStateOf(false) }
    var pinEnabled by remember { mutableStateOf(pinStore.isPinEnabled()) }
    var biometricTimeout by remember { mutableStateOf(biometricTimeoutStore.getTimeout()) }
    var biometricLockOnLaunch by remember { mutableStateOf(biometricTimeoutStore.isLockOnLaunchEnabled()) }
    var showBunkerScreen by remember { mutableStateOf(false) }
    var showWalletDescriptorScreen by remember { mutableStateOf(false) }
    var descriptorCount by remember { mutableIntStateOf(0) }
    val bunkerUrl by BunkerService.bunkerUrl.collectAsState()
    val bunkerStatus by BunkerService.status.collectAsState()
    var certificatePins by remember { mutableStateOf(keepMobile.getCertificatePinsCompat()) }
    var profileRelays by remember { mutableStateOf(emptyList<String>()) }
    var showSecuritySettings by remember { mutableStateOf(false) }
    var showExportLogs by remember { mutableStateOf(false) }
    var showEventLog by remember { mutableStateOf(false) }
    var showBackupRestore by remember { mutableStateOf(false) }
    var showRecoverNsec by remember { mutableStateOf(false) }
    var showCreateAccountScreen by remember { mutableStateOf(false) }
    var showMnemonicRecoveryScreen by remember { mutableStateOf(false) }
    var activeDidBackup by remember { mutableStateOf<Boolean?>(null) }
    var showSeedWordsScreen by remember { mutableStateOf(false) }
    val seedWordsData = remember { SecureShareData(MAX_SEED_WORDS_LENGTH) }
    var seedWordsLoading by remember { mutableStateOf(false) }
    var seedWordsRequestToken by remember { mutableStateOf(0) }

    DisposableEffect(Unit) {
        onDispose { seedWordsData.clear() }
    }

    val proxyConfig = remember { runCatching { keepMobile.getProxyConfig() }.getOrNull() }
    var proxyEnabled by remember { mutableStateOf(proxyConfig?.enabled == true) }
    var proxyPort by remember { mutableStateOf(proxyConfig?.port?.toInt() ?: 9050) }

    val handleKillSwitchToggle: (Boolean) -> Unit = { newValue ->
        if (newValue) {
            showKillSwitchConfirmDialog = true
        } else if (biometricAvailable) {
            coroutineScope.launch {
                // Downgrade action: force a live prompt so an open biometric-timeout
                // window can't be ridden to disable the kill switch silently.
                val authenticated = onBiometricAuth?.invoke(
                    appContext.getString(R.string.main_disable_kill_switch_title),
                    appContext.getString(R.string.main_disable_kill_switch_subtitle),
                    true,
                ) ?: false
                if (authenticated) {
                    val updated = withContext(Dispatchers.IO) {
                        runCatching { keepMobile.setKillSwitch(false) }.isSuccess
                    }
                    if (updated) killSwitchEnabled = false
                }
            }
        } else {
            // Biometrics unavailable: fall back to PIN so the kill switch cannot lock the
            // user out of signing permanently (the switch is enabled here only when a PIN
            // is set). Disabling still requires a verified auth factor.
            showKillSwitchPinPrompt = true
        }
    }

    // Runs [action] only after a verified auth factor: biometric when available, else a
    // PIN prompt, else (no factor configured) immediately, consistent with the rest of the
    // app in that config. Used to gate security-downgrade actions like clearing a cert pin.
    val requireAuthThen: (String, String, String, suspend () -> Unit) -> Unit =
        { title, message, confirmLabel, action ->
            when {
                biometricAvailable -> coroutineScope.launch {
                    // Downgrade gate (cert-pin clear/retire, app-lock weakening): force a
                    // live prompt rather than accepting an open biometric-timeout window.
                    if (onBiometricAuth?.invoke(title, message, true) == true) action()
                }
                pinEnabled -> {
                    authGateTitle = title
                    authGateMessage = message
                    authGateConfirm = confirmLabel
                    pendingAuthGateAction = action
                }
                else -> coroutineScope.launch { action() }
            }
        }

    val accountActions = remember {
        AccountActions(
            keepMobile = keepMobile,
            storage = storage,
            coroutineScope = coroutineScope,
            appContext = appContext,
            onBiometricRequest = onBiometricRequest,
            onAccountSwitched = onAccountSwitched,
            onAccountDeleted = {
                try {
                    permissionStore.logSelfEvent(AUDIT_OP_ACCOUNT_DELETE)
                } catch (c: CancellationException) {
                    throw c
                } catch (_: Throwable) {
                    // best-effort audit; a failed append must not block deletion
                }
            },
            onStateChanged = { state ->
                hasShare = state.hasShare
                shareInfo = state.shareInfo
                activeAccountKey = state.activeAccountKey
                allAccounts = state.allAccounts
                relays = state.relays
                profileRelays = state.profileRelays
                activeDidBackup = state.activeDidBackup
            }
        )
    }

    LaunchedEffect(relays) {
        accountActions.setCurrentRelays(relays)
    }

    suspend fun refreshCertificatePins() {
        certificatePins = withContext(Dispatchers.IO) { keepMobile.getCertificatePinsCompat() }
    }

    fun loadProfileRelays(accountKey: String?): List<String> {
        if (accountKey == null) return emptyList()
        return runCatching { keepMobile.getRelayConfig(accountKey).profileRelays }.getOrDefault(emptyList())
    }

    suspend fun saveProfileRelays(updated: List<String>) {
        val key = withContext(Dispatchers.IO) { storage.getActiveShareKey() } ?: return
        withContext(Dispatchers.IO) {
            val existing = runCatching { keepMobile.getRelayConfig(key) }.getOrNull()
                ?: RelayConfigInfo(emptyList(), emptyList(), emptyList())
            keepMobile.saveRelayConfig(key, RelayConfigInfo(existing.frostRelays, updated, existing.bunkerRelays))
        }
    }

    LaunchedEffect(Unit) {
        val initial = withContext(Dispatchers.IO) {
            val a = storage.listAllShares().map { it.toAccountInfo() }
            val k = storage.getActiveShareKey()
            val config = runCatching { keepMobile.getRelayConfig(k) }.getOrNull()
                ?: RelayConfigInfo(emptyList(), emptyList(), emptyList())
            val r = config.frostRelays
            val pr = config.profileRelays
            AccountInitial(a, k, r, pr)
        }
        allAccounts = initial.accounts
        activeAccountKey = initial.activeKey
        relays = initial.relays
        profileRelays = initial.profileRelays
    }

    LaunchedEffect(Unit) {
        DescriptorSessionManager.clearAll()
        DescriptorSessionManager.activate()
        runCatching {
            withContext(Dispatchers.IO) {
                keepMobile.walletDescriptorSetCallbacks(DescriptorSessionManager.createCallbacks())
            }
        }.onSuccess {
            DescriptorSessionManager.setCallbacksRegistered(true)
        }.onFailure {
            if (it is CancellationException) throw it
            Log.e("MainActivity", "Failed to set descriptor callbacks", it)
            DescriptorSessionManager.setCallbacksRegistered(false)
        }
        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            repeat(Int.MAX_VALUE) {
                val pollResult = withContext(Dispatchers.IO) {
                    val h = keepMobile.hasShare()
                    val s = keepMobile.getShareInfo()
                    val a = storage.listAllShares().map { it.toAccountInfo() }
                    val k = storage.getActiveShareKey()
                    val dc = if (h) {
                        runCatching { keepMobile.walletDescriptorList().size }
                            .onFailure { if (it is CancellationException) throw it }
                            .getOrDefault(descriptorCount)
                    } else 0
                    val db = runCatching { keepMobile.getActiveShareMetadata()?.didBackup }
                        .onFailure { if (it is CancellationException) throw it }
                        .getOrNull()
                    PollResult(h, s, a, k, dc, db)
                }
                hasShare = pollResult.hasShare
                shareInfo = pollResult.shareInfo
                allAccounts = pollResult.allAccounts
                activeAccountKey = pollResult.activeAccountKey
                descriptorCount = pollResult.descriptorCount
                activeDidBackup = pollResult.activeDidBackup
                refreshCertificatePins()
                profileRelays = withContext(Dispatchers.IO) { loadProfileRelays(pollResult.activeAccountKey) }
                delay(10_000)
            }
        }
    }

    if (showKillSwitchConfirmDialog) {
        KillSwitchConfirmDialog(
            onConfirm = {
                coroutineScope.launch {
                    val updated = withContext(Dispatchers.IO) {
                        runCatching { keepMobile.setKillSwitch(true) }.isSuccess
                    }
                    if (updated) {
                        killSwitchEnabled = true
                    } else {
                        Toast.makeText(
                            appContext,
                            appContext.getString(R.string.main_enable_kill_switch_failed),
                            Toast.LENGTH_LONG,
                        ).show()
                    }
                    showKillSwitchConfirmDialog = false
                }
            },
            onDismiss = { showKillSwitchConfirmDialog = false }
        )
    }

    if (showKillSwitchPinPrompt) {
        PinPromptDialog(
            title = stringResource(R.string.main_disable_kill_switch_title),
            message = stringResource(R.string.main_disable_kill_switch_subtitle),
            confirmLabel = stringResource(R.string.settings_pin_disable),
            onVerify = { pin ->
                val verified = withContext(Dispatchers.IO) { pinStore.verifyPin(pin) }
                if (!verified) {
                    false
                } else {
                    val updated = withContext(Dispatchers.IO) {
                        runCatching { keepMobile.setKillSwitch(false) }.isSuccess
                    }
                    if (updated) killSwitchEnabled = false
                    updated
                }
            },
            onDismiss = { showKillSwitchPinPrompt = false }
        )
    }

    pendingAuthGateAction?.let { action ->
        PinPromptDialog(
            title = authGateTitle,
            message = authGateMessage,
            confirmLabel = authGateConfirm,
            onVerify = { pin ->
                val verified = withContext(Dispatchers.IO) { pinStore.verifyPin(pin) }
                if (verified) {
                    action()
                    true
                } else {
                    false
                }
            },
            onDismiss = { pendingAuthGateAction = null }
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
                val applyTimeout: suspend () -> Unit = {
                    val saved = withContext(Dispatchers.IO) { biometricTimeoutStore.setTimeout(newTimeout) }
                    if (saved) biometricTimeout = newTimeout
                }
                // A larger value is a longer window before re-auth, so it weakens the gate;
                // require a fresh factor. Shortening it (or every-time) applies immediately.
                if (newTimeout > biometricTimeout) {
                    requireAuthThen(
                        appContext.getString(R.string.settings_biometric_timeout_reauth_title),
                        appContext.getString(R.string.settings_biometric_timeout_reauth_text),
                        appContext.getString(R.string.settings_reauth_confirm),
                        applyTimeout,
                    )
                } else {
                    coroutineScope.launch { applyTimeout() }
                }
            },
            biometricLockOnLaunch = biometricLockOnLaunch,
            onBiometricLockOnLaunchChanged = { enabled ->
                val applyLockOnLaunch: suspend () -> Unit = {
                    val saved = withContext(Dispatchers.IO) { biometricTimeoutStore.setLockOnLaunch(enabled) }
                    if (saved) biometricLockOnLaunch = enabled
                }
                // Disabling app-lock weakens the gate; require a fresh factor. Enabling applies immediately.
                if (!enabled) {
                    requireAuthThen(
                        appContext.getString(R.string.settings_biometric_lock_disable_reauth_title),
                        appContext.getString(R.string.settings_biometric_lock_disable_reauth_text),
                        appContext.getString(R.string.settings_reauth_confirm),
                        applyLockOnLaunch,
                    )
                } else {
                    coroutineScope.launch { applyLockOnLaunch() }
                }
            },
            biometricAvailable = biometricAvailable,
            killSwitchEnabled = killSwitchEnabled,
            onKillSwitchToggle = handleKillSwitchToggle,
            onExportLogs = {
                showSecuritySettings = false
                showExportLogs = true
            },
            onViewActivityLog = {
                showSecuritySettings = false
                showEventLog = true
            },
            onDismiss = { showSecuritySettings = false }
        )
        return
    }

    if (showExportLogs) {
        ExportLogsScreen(
            keepMobile = keepMobile,
            storage = storage,
            signingAuditLog = signingAuditLog,
            permissionStore = permissionStore,
            eventLogStore = eventLogStore,
            foregroundServiceEnabled = foregroundServiceEnabled,
            onDismiss = { showExportLogs = false }
        )
        return
    }

    if (showEventLog) {
        if (eventLogStore != null) {
            EventLogScreen(
                eventLogStore = eventLogStore,
                onDismiss = { showEventLog = false }
            )
            return
        }
        showEventLog = false
    }

    if (showBackupRestore) {
        BackupRestoreScreen(
            keepMobile = keepMobile,
            storage = storage,
            onGetCipher = { requireBiometricReady(); getShareAwareCipher(storage) },
            onBiometricAuth = { cipher, callback ->
                onBiometricRequest(
                    appContext.getString(R.string.main_vault_backup_title),
                    appContext.getString(R.string.main_vault_backup_subtitle),
                    cipher,
                    callback
                )
            },
            onDismiss = { showBackupRestore = false }
        )
        return
    }

    if (showRecoverNsec) {
        RecoverNsecScreen(
            keepMobile = keepMobile,
            storage = storage,
            shareInfo = shareInfo,
            onGetCipher = { requireBiometricReady(); getShareAwareCipher(storage) },
            onBiometricAuth = { cipher, callback ->
                onBiometricRequest(
                    appContext.getString(R.string.main_recover_nsec_title),
                    appContext.getString(R.string.main_recover_nsec_subtitle),
                    cipher,
                    callback
                )
            },
            onDismiss = { showRecoverNsec = false }
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

    if (showRelayAuthWhitelistScreen) {
        val whitelistStore = (LocalContext.current.applicationContext as? KeepMobileApp)?.getRelayAuthWhitelistStore()
        if (whitelistStore != null) {
            RelayAuthWhitelistScreen(
                store = whitelistStore,
                onDismiss = { showRelayAuthWhitelistScreen = false }
            )
            return
        }
        LaunchedEffect(Unit) { showRelayAuthWhitelistScreen = false }
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
            signingAuditLog = signingAuditLog,
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
            onGetCipher = { requireBiometricReady(); getShareAwareCipher(storage) },
            onBiometricAuth = { cipher, callback ->
                onBiometricRequest(
                    appContext.getString(R.string.main_export_share_title),
                    appContext.getString(R.string.main_export_share_subtitle),
                    cipher,
                    callback
                )
            },
            onDismiss = { showExportScreen = false }
        )
        return
    }

    if (showExportNcryptsecScreen && currentShareInfoForScreens != null) {
        ExportNcryptsecScreen(
            keepMobile = keepMobile,
            shareInfo = currentShareInfoForScreens,
            storage = storage,
            onGetCipher = { requireBiometricReady(); getShareAwareCipher(storage) },
            onBiometricAuth = { cipher, callback ->
                onBiometricRequest(
                    appContext.getString(R.string.main_export_encrypted_key_title),
                    appContext.getString(R.string.main_export_encrypted_key_subtitle),
                    cipher,
                    callback
                )
            },
            onDismiss = { showExportNcryptsecScreen = false }
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
            keepMobile = keepMobile,
            bunkerUrl = bunkerUrl,
            bunkerStatus = bunkerStatus,
            onToggleBunker = onBunkerServiceChanged,
            onDismiss = { showBunkerScreen = false }
        )
        return
    }

    if (showWalletDescriptorScreen) {
        WalletDescriptorScreen(
            keepMobile = keepMobile,
            onDismiss = { showWalletDescriptorScreen = false }
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
            onRenameAccount = { account, newName ->
                accountActions.renameAccount(account, newName)
            },
            onImportAccount = {
                showAccountSwitcher = false
                showImportScreen = true
            },
            onImportNsec = {
                showAccountSwitcher = false
                showImportNsecScreen = true
            },
            onCreateAccount = {
                showAccountSwitcher = false
                showCreateAccountScreen = true
            },
            onRecoverMnemonic = {
                showAccountSwitcher = false
                showMnemonicRecoveryScreen = true
            },
            onDismiss = { showAccountSwitcher = false }
        )
    }

    if (showImportScreen) {
        ImportShareScreen(
            onImport = { data, passphrase, name, cipher ->
                accountActions.importShare(data, passphrase, name, cipher) { importState = it }
            },
            onGetCipher = {
                requireBiometricReady()
                storage.getCipherForEncryption()
            },
            onBiometricAuth = { cipher, callback ->
                onBiometricRequest(
                    appContext.getString(R.string.main_import_share_title),
                    appContext.getString(R.string.main_import_share_subtitle),
                    cipher,
                    callback
                )
            },
            onDismiss = {
                showImportScreen = false
                importState = ImportState.Idle
            },
            importState = importState
        )
        return
    }

    if (showCreateGroupScreen) {
        val groupRelays = relays.ifEmpty {
            runCatching { keepMobile.getRelayConfig(null).frostRelays }.getOrDefault(emptyList())
        }
        CreateGroupScreen(
            relays = groupRelays,
            onCreateGroup = { config, name, cipher ->
                accountActions.createGroup(config, name, cipher) { createGroupState = it }
            },
            onDkgBegin = { name -> accountActions.dkgBegin(name) },
            onCancel = { accountActions.cancelDkg() },
            onGetCipher = {
                requireBiometricReady()
                storage.getCipherForEncryption()
            },
            onBiometricAuth = { cipher, callback ->
                onBiometricRequest(
                    appContext.getString(R.string.main_create_group_title),
                    appContext.getString(R.string.main_create_group_subtitle),
                    cipher,
                    callback
                )
            },
            onDismiss = {
                showCreateGroupScreen = false
                createGroupState = CreateGroupState.Idle
            },
            createGroupState = createGroupState
        )
        return
    }

    if (showImportNsecScreen) {
        ImportNsecScreen(
            onImport = { nsec, name, cipher ->
                accountActions.importNsec(nsec, name, cipher) { importState = it }
            },
            onGetCipher = {
                requireBiometricReady()
                storage.getCipherForEncryption()
            },
            onBiometricAuth = { cipher, callback ->
                onBiometricRequest(
                    appContext.getString(R.string.main_import_nsec_title),
                    appContext.getString(R.string.main_import_nsec_subtitle),
                    cipher,
                    callback
                )
            },
            onDismiss = {
                showImportNsecScreen = false
                importState = ImportState.Idle
            },
            importState = importState
        )
        return
    }

    if (showCreateAccountScreen) {
        CreateAccountScreen(
            keepMobile = keepMobile,
            onCreateAccount = { mnemonic, passphrase, name, cipher ->
                accountActions.createAccountFromMnemonic(mnemonic, passphrase, name, cipher) { importState = it }
            },
            onGetCipher = {
                requireBiometricReady()
                storage.getCipherForEncryption()
            },
            onBiometricAuth = { cipher, callback ->
                onBiometricRequest(
                    appContext.getString(R.string.main_create_account_title),
                    appContext.getString(R.string.main_create_account_subtitle),
                    cipher,
                    callback
                )
            },
            onDismiss = {
                showCreateAccountScreen = false
                importState = ImportState.Idle
            },
            importState = importState
        )
        return
    }

    if (showSeedWordsScreen) {
        val activeAccount = remember(activeAccountKey, allAccounts) {
            activeAccountKey?.let { key -> allAccounts.firstOrNull { it.groupPubkeyHex == key } }
        }
        val confirmBackupFailedMessage = stringResource(R.string.main_confirm_backup_failed)
        SeedWordsScreen(
            mnemonicData = seedWordsData,
            isLoading = seedWordsLoading,
            didBackup = activeDidBackup == true,
            onConfirmBackedUp = {
                val acct = activeAccount
                if (acct != null) {
                    accountActions.markBackedUp(acct) { success ->
                        if (success) {
                            seedWordsData.clear()
                            showSeedWordsScreen = false
                        } else if (showSeedWordsScreen) {
                            // Only surface the toast while the sheet is still attached; ON_STOP
                            // may have already torn it down and called onDismiss.
                            Toast.makeText(
                                appContext,
                                confirmBackupFailedMessage,
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                    }
                }
            },
            onDismiss = {
                seedWordsData.clear()
                showSeedWordsScreen = false
            }
        )
        return
    }

    if (showMnemonicRecoveryScreen) {
        MnemonicRecoveryScreen(
            keepMobile = keepMobile,
            onCreateAccount = { mnemonic, passphrase, name, cipher ->
                accountActions.createAccountFromMnemonic(mnemonic, passphrase, name, cipher) { importState = it }
            },
            onGetCipher = {
                requireBiometricReady()
                storage.getCipherForEncryption()
            },
            onBiometricAuth = { cipher, callback ->
                onBiometricRequest(
                    appContext.getString(R.string.main_import_from_seed_words_title),
                    appContext.getString(R.string.main_import_from_seed_words_subtitle),
                    cipher,
                    callback
                )
            },
            onDismiss = {
                showMnemonicRecoveryScreen = false
                importState = ImportState.Idle
            },
            importState = importState
        )
        return
    }

    if (pinMismatchInfo != null) {
        PinMismatchDialog(
            hostname = pinMismatchInfo.hostname,
            onClearAndRetry = {
                // Clearing a pin re-opens trust-on-first-use for this host (here, right after
                // a possible-MITM mismatch), so require a fresh auth factor first.
                requireAuthThen(
                    appContext.getString(R.string.settings_cert_pins_clear_dialog_title),
                    appContext.getString(R.string.settings_cert_pins_clear_dialog_text, pinMismatchInfo.hostname),
                    appContext.getString(R.string.settings_cert_pins_clear),
                ) {
                    withContext(Dispatchers.IO) { onClearCertificatePin(pinMismatchInfo.hostname) }
                    refreshCertificatePins()
                    onReconnectRelays()
                }
            },
            onDismiss = onDismissPinMismatch
        )
    }

    val biometricUnavailableMessage = stringResource(R.string.main_biometric_unavailable)
    val initEncryptionFailedMessage = stringResource(R.string.main_init_encryption_failed)
    val connectRelaysTitle = stringResource(R.string.main_connect_relays_title)
    val connectRelaysSubtitle = stringResource(R.string.main_connect_relays_subtitle)

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
                    pendingRequests = appLiveState?.pendingRequests ?: emptyList(),
                    onApproveRequest = { id ->
                        coroutineScope.launch {
                            val authed = if (biometricAvailable && onBiometricAuth != null) {
                                // Signing approval, not a downgrade: respect the biometric-
                                // timeout window (forcePrompt=false) so batch approvals work
                                // as configured.
                                onBiometricAuth.invoke(
                                    appContext.getString(R.string.cosign_request_label),
                                    appContext.getString(R.string.cosign_approve),
                                    false,
                                )
                            } else {
                                true
                            }
                            if (authed) {
                                withContext(Dispatchers.IO) {
                                    runCatching { keepMobile.approveRequest(id) }
                                }
                            }
                        }
                    },
                    onRejectRequest = { id ->
                        coroutineScope.launch(Dispatchers.IO) {
                            runCatching { keepMobile.rejectRequest(id) }
                        }
                    },
                    isConnected = isConnected,
                    isConnecting = isConnecting,
                    connectionError = connectionError,
                    relays = relays,
                    securityLevel = securityLevel,
                    killSwitchEnabled = killSwitchEnabled,
                    biometricAvailable = biometricAvailable,
                    pinEnabled = pinEnabled,
                    onShareDetailsClick = { showShareDetails = true },
                    onAccountSwitcherClick = { showAccountSwitcher = true },
                    onImport = { showImportScreen = true },
                    onImportNsec = { showImportNsecScreen = true },
                    onCreateAccount = { showCreateAccountScreen = true },
                    onRecoverMnemonic = { showMnemonicRecoveryScreen = true },
                    onCreateGroup = { showCreateGroupScreen = true },
                    onConnect = {
                        coroutineScope.launch {
                            val cipher = try {
                                requireBiometricReady()
                                withContext(Dispatchers.IO) {
                                    getShareAwareCipher(storage)
                                }
                            } catch (e: BiometricHelper.BiometricNotReadyException) {
                                Toast.makeText(appContext, e.message ?: biometricUnavailableMessage, Toast.LENGTH_LONG).show()
                                return@launch
                            }
                            if (cipher == null) {
                                Toast.makeText(appContext, initEncryptionFailedMessage, Toast.LENGTH_SHORT).show()
                                return@launch
                            }
                            onBiometricRequest(connectRelaysTitle, connectRelaysSubtitle, cipher) { authedCipher ->
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
                    descriptorCount = descriptorCount,
                    onConnectedAppsClick = { showConnectedApps = true },
                    onSignPolicyClick = { showSignPolicyScreen = true },
                    onRelayAuthWhitelistClick = { showRelayAuthWhitelistScreen = true },
                    onPermissionsClick = { showPermissionsScreen = true },
                    onHistoryClick = { showHistoryScreen = true },
                    onBunkerClick = { showBunkerScreen = true },
                    onWalletDescriptorClick = { showWalletDescriptorScreen = true }
                )
            }

            composable(Route.Settings.route) {
                SettingsTab(
                    hasShare = hasShare,
                    relays = relays,
                    profileRelays = profileRelays,
                    certificatePins = certificatePins,
                    proxyEnabled = proxyEnabled,
                    proxyPort = proxyPort,
                    autoStartEnabled = autoStartEnabled,
                    foregroundServiceEnabled = foregroundServiceEnabled,
                    isConnected = isConnected,
                    onAddRelay = { relay ->
                        if (!relays.contains(relay) && relays.size < 20) {
                            coroutineScope.launch {
                                val check = withContext(Dispatchers.IO) { checkRelayHost(relay) }
                                if (check == RelayHostCheck.REACHABLE) {
                                    val updated = relays + relay
                                    relays = updated
                                    onRelaysChanged(updated)
                                } else {
                                    showRelayHostCheckToast(appContext, check)
                                }
                            }
                        }
                    },
                    onRemoveRelay = { relay ->
                        val updated = relays - relay
                        relays = updated
                        onRelaysChanged(updated)
                    },
                    onAddProfileRelay = { relay ->
                        if (!profileRelays.contains(relay) && profileRelays.size < 20) {
                            coroutineScope.launch {
                                val check = withContext(Dispatchers.IO) { checkRelayHost(relay) }
                                if (check == RelayHostCheck.REACHABLE) {
                                    val updated = profileRelays + relay
                                    profileRelays = updated
                                    saveProfileRelays(updated)
                                } else {
                                    showRelayHostCheckToast(appContext, check)
                                }
                            }
                        }
                    },
                    onRemoveProfileRelay = { relay ->
                        val updated = profileRelays - relay
                        profileRelays = updated
                        coroutineScope.launch { saveProfileRelays(updated) }
                    },
                    onStagePin = { hostname, spkiHash ->
                        coroutineScope.launch {
                            val staged = withContext(Dispatchers.IO) {
                                onStageCertificatePin(hostname, spkiHash)
                            }
                            refreshCertificatePins()
                            val message = if (staged) {
                                appContext.getString(R.string.settings_cert_pins_staged, hostname)
                            } else {
                                appContext.getString(R.string.settings_cert_pins_stage_failed)
                            }
                            Toast.makeText(appContext, message, Toast.LENGTH_SHORT).show()
                        }
                    },
                    onRetirePin = { hostname, spkiHash ->
                        // Removing a pin can leave a host unpinned (re-opening TOFU), so gate
                        // it behind auth too, otherwise the clear-all gate is bypassable by
                        // retiring pins one at a time.
                        requireAuthThen(
                            appContext.getString(R.string.settings_cert_pins_clear_dialog_title),
                            appContext.getString(R.string.settings_cert_pins_clear_dialog_text, hostname),
                            appContext.getString(R.string.settings_cert_pins_clear),
                        ) {
                            val removal = withContext(Dispatchers.IO) {
                                onRemoveCertificatePin(hostname, spkiHash)
                            }
                            refreshCertificatePins()
                            if (removal?.hostNowUnpinned == true) {
                                Toast.makeText(
                                    appContext,
                                    appContext.getString(R.string.settings_cert_pins_unpinned_warning, hostname),
                                    Toast.LENGTH_LONG
                                ).show()
                            }
                        }
                    },
                    onClearAllPins = {
                        requireAuthThen(
                            appContext.getString(R.string.settings_cert_pins_clear_all_dialog_title),
                            appContext.getString(R.string.settings_cert_pins_clear_all_dialog_text),
                            appContext.getString(R.string.settings_cert_pins_clear_all),
                        ) {
                            withContext(Dispatchers.IO) { onClearAllCertificatePins() }
                            refreshCertificatePins()
                        }
                    },
                    onProxyActivate = { port ->
                        coroutineScope.launch {
                            withContext(Dispatchers.IO) {
                                keepMobile.saveProxyConfig(ProxyConfigInfo(true, port.toUShort()))
                            }
                            proxyEnabled = true
                            proxyPort = port
                            if (isConnected) onReconnectRelays()
                        }
                    },
                    onProxyDeactivate = {
                        coroutineScope.launch {
                            withContext(Dispatchers.IO) {
                                keepMobile.saveProxyConfig(ProxyConfigInfo(false, proxyPort.toUShort()))
                            }
                            proxyEnabled = false
                            if (isConnected) onReconnectRelays()
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
                    onSecurityClick = { showSecuritySettings = true },
                    onBackupClick = { showBackupRestore = true },
                    onSigningHistoryClick = { showHistoryScreen = true },
                    onClearLogsAndActivity = {
                        withContext(Dispatchers.IO) {
                            permissionStore.cleanupExpired()
                        }
                    }
                )
            }

            composable(Route.Account.route) {
                AccountTab(
                    hasShare = hasShare,
                    shareInfo = shareInfo,
                    allAccounts = allAccounts,
                    activeDidBackup = activeDidBackup,
                    onAccountSwitcherClick = { showAccountSwitcher = true },
                    onShareDetailsClick = { showShareDetails = true },
                    onExportClick = { showExportScreen = true },
                    onExportNcryptsecClick = { showExportNcryptsecScreen = true },
                    onViewSeedWords = {
                        val acct = activeAccountKey?.let { key ->
                            allAccounts.firstOrNull { it.groupPubkeyHex == key }
                        }
                        if (acct != null) {
                            val token = ++seedWordsRequestToken
                            seedWordsLoading = true
                            seedWordsData.clear()
                            showSeedWordsScreen = true
                            accountActions.viewSeedWords(
                                acct,
                                onResult = { mnemonic ->
                                    if (token != seedWordsRequestToken || !showSeedWordsScreen) return@viewSeedWords
                                    if (mnemonic != null) {
                                        if (!seedWordsData.updateFromBytes(mnemonic)) {
                                            Log.w("MainActivity", "Seed words exceeded MAX_SEED_WORDS_LENGTH=$MAX_SEED_WORDS_LENGTH; truncated/rejected")
                                        }
                                    }
                                    seedWordsLoading = false
                                },
                                onDismiss = { success ->
                                    if (token != seedWordsRequestToken) return@viewSeedWords
                                    seedWordsLoading = false
                                    if (!success) {
                                        seedWordsData.clear()
                                        showSeedWordsScreen = false
                                    }
                                }
                            )
                        }
                    },
                    onImport = { showImportScreen = true },
                    onImportNsec = { showImportNsecScreen = true },
                    onCreateAccount = { showCreateAccountScreen = true },
                    onRecoverMnemonic = { showMnemonicRecoveryScreen = true },
                    onRecoverNsec = { showRecoverNsec = true },
                    onCreateGroup = { showCreateGroupScreen = true }
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
    pendingRequests: List<SignRequest>,
    onApproveRequest: (String) -> Unit,
    onRejectRequest: (String) -> Unit,
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
    onCreateAccount: () -> Unit,
    onRecoverMnemonic: () -> Unit,
    onCreateGroup: () -> Unit,
    onConnect: () -> Unit,
    biometricAvailable: Boolean,
    pinEnabled: Boolean,
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
        Row(verticalAlignment = Alignment.CenterVertically) {
            Image(
                painter = painterResource(R.drawable.keep_crest),
                contentDescription = null,
                modifier = Modifier.size(40.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = stringResource(R.string.main_home_title),
                style = MaterialTheme.typography.headlineLarge
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        SecurityLevelBadge(securityLevel)
        Spacer(modifier = Modifier.height(16.dp))

        // Pending co-sign requests, surfaced at the top so they're seen and acted
        // on immediately (not buried below the status cards).
        if (pendingRequests.isNotEmpty()) {
            pendingRequests.forEach { req ->
                KeepCard(contentPadding = PaddingValues(0.dp)) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            stringResource(R.string.cosign_request_label),
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            req.describe(),
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = { onApproveRequest(req.id) }) {
                                Text(stringResource(R.string.cosign_approve))
                            }
                            OutlinedButton(onClick = { onRejectRequest(req.id) }) {
                                Text(stringResource(R.string.cosign_reject))
                            }
                        }
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
            }
        }

        KillSwitchCard(
            enabled = killSwitchEnabled,
            onToggle = onKillSwitchToggle,
            toggleEnabled = biometricAvailable || pinEnabled
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
        } else {
            NoShareCard(
                onImport = onImport,
                onImportNsec = onImportNsec,
                onCreateAccount = onCreateAccount,
                onRecoverMnemonic = onRecoverMnemonic,
                onCreateGroup = onCreateGroup
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
private fun AppsTab(
    hasShare: Boolean,
    bunkerStatus: BunkerStatus,
    descriptorCount: Int,
    onConnectedAppsClick: () -> Unit,
    onSignPolicyClick: () -> Unit,
    onRelayAuthWhitelistClick: () -> Unit,
    onPermissionsClick: () -> Unit,
    onHistoryClick: () -> Unit,
    onBunkerClick: () -> Unit,
    onWalletDescriptorClick: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(text = stringResource(R.string.main_apps_title), style = MaterialTheme.typography.headlineLarge)
        Spacer(modifier = Modifier.height(16.dp))

        if (hasShare) {
            ConnectedAppsCard(onClick = onConnectedAppsClick)
            Spacer(modifier = Modifier.height(16.dp))

            Nip55SettingsCard(
                onSignPolicyClick = onSignPolicyClick,
                onRelayAuthWhitelistClick = onRelayAuthWhitelistClick,
                onPermissionsClick = onPermissionsClick,
                onHistoryClick = onHistoryClick
            )
            Spacer(modifier = Modifier.height(16.dp))

            BunkerCard(
                status = bunkerStatus,
                onClick = onBunkerClick
            )
            Spacer(modifier = Modifier.height(16.dp))

            WalletDescriptorCard(
                descriptorCount = descriptorCount,
                onClick = onWalletDescriptorClick
            )
        } else {
            KeepCard(contentPadding = PaddingValues(0.dp)) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        stringResource(R.string.main_apps_no_share),
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
    profileRelays: List<String>,
    certificatePins: List<CertificatePin>,
    proxyEnabled: Boolean,
    proxyPort: Int,
    autoStartEnabled: Boolean,
    foregroundServiceEnabled: Boolean,
    isConnected: Boolean,
    onAddRelay: (String) -> Unit,
    onRemoveRelay: (String) -> Unit,
    onAddProfileRelay: (String) -> Unit,
    onRemoveProfileRelay: (String) -> Unit,
    onStagePin: (String, String) -> Unit,
    onRetirePin: (String, String) -> Unit,
    onClearAllPins: () -> Unit,
    onProxyActivate: (Int) -> Unit,
    onProxyDeactivate: () -> Unit,
    onAutoStartToggle: (Boolean) -> Unit,
    onForegroundServiceToggle: (Boolean) -> Unit,
    onSecurityClick: () -> Unit,
    onBackupClick: () -> Unit,
    onSigningHistoryClick: () -> Unit,
    onClearLogsAndActivity: suspend () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var databaseSizeMb by remember { mutableStateOf("") }

    suspend fun refreshDatabaseSize() {
        withContext(Dispatchers.IO) {
            val dbFile = context.getDatabasePath("nip55_permissions.db")
            val size = if (dbFile.exists()) dbFile.length() else 0L
            databaseSizeMb = "%.2f".format(size / (1024.0 * 1024.0))
        }
    }

    LaunchedEffect(Unit) { refreshDatabaseSize() }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(text = stringResource(R.string.main_settings_title), style = MaterialTheme.typography.headlineLarge)
        Spacer(modifier = Modifier.height(16.dp))

        if (hasShare) {
            ShareSettingsSection(
                relays = relays,
                profileRelays = profileRelays,
                certificatePins = certificatePins,
                proxyEnabled = proxyEnabled,
                proxyPort = proxyPort,
                onAddRelay = onAddRelay,
                onRemoveRelay = onRemoveRelay,
                onAddProfileRelay = onAddProfileRelay,
                onRemoveProfileRelay = onRemoveProfileRelay,
                onStagePin = onStagePin,
                onRetirePin = onRetirePin,
                onClearAllPins = onClearAllPins,
                onProxyActivate = onProxyActivate,
                onProxyDeactivate = onProxyDeactivate
            )
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

        BackupSettingsCard(onClick = onBackupClick)
        Spacer(modifier = Modifier.height(16.dp))

        if (hasShare) {
            SigningHistoryCard(onClick = onSigningHistoryClick)
            Spacer(modifier = Modifier.height(16.dp))
        }

        Spacer(modifier = Modifier.height(8.dp))
        HorizontalDivider()
        Spacer(modifier = Modifier.height(16.dp))

        DatabaseManagementSection(
            databaseSizeMb = databaseSizeMb,
            onCleanup = {
                scope.launch {
                    onClearLogsAndActivity()
                    refreshDatabaseSize()
                }
            }
        )

        SettingsFooterLinks()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SecuritySettingsCard(onClick: () -> Unit) {
    KeepCard(onClick = onClick) {
        KeepListRow(
            title = stringResource(R.string.main_security_title),
            subtitle = stringResource(R.string.main_security_subtitle),
            trailing = { KeepRowAction(stringResource(R.string.main_manage)) }
        )
    }
}

@Composable
private fun SigningHistoryCard(onClick: () -> Unit) {
    KeepCard(onClick = onClick) {
        KeepListRow(
            title = stringResource(R.string.main_signing_history_title),
            subtitle = stringResource(R.string.main_signing_history_subtitle),
            trailing = { KeepRowAction(stringResource(R.string.main_view)) }
        )
    }
}

@Composable
private fun AccountTab(
    hasShare: Boolean,
    shareInfo: ShareInfo?,
    allAccounts: List<AccountInfo>,
    activeDidBackup: Boolean?,
    onAccountSwitcherClick: () -> Unit,
    onShareDetailsClick: () -> Unit,
    onExportClick: () -> Unit,
    onExportNcryptsecClick: () -> Unit,
    onViewSeedWords: () -> Unit,
    onImport: () -> Unit,
    onImportNsec: () -> Unit,
    onCreateAccount: () -> Unit,
    onRecoverMnemonic: () -> Unit,
    onRecoverNsec: () -> Unit,
    onCreateGroup: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(text = stringResource(R.string.main_keys_title), style = MaterialTheme.typography.headlineLarge)
        Spacer(modifier = Modifier.height(16.dp))

        if (hasShare && activeDidBackup == false) {
            BackupPromptCard(onClick = onViewSeedWords)
            Spacer(modifier = Modifier.height(16.dp))
        }

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

            KeepCard(contentPadding = PaddingValues(0.dp)) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(stringResource(R.string.main_key_management), style = MaterialTheme.typography.titleMedium)
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedButton(
                        onClick = onViewSeedWords,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(stringResource(R.string.main_view_seed_words))
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = onExportClick,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(stringResource(R.string.main_export_share_button))
                    }
                    if (shareInfo.threshold == 1u.toUShort() && shareInfo.totalShares == 1u.toUShort()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = onExportNcryptsecClick,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(stringResource(R.string.main_export_ncryptsec))
                        }
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
                            Text(stringResource(R.string.main_import_share_button))
                        }
                        OutlinedButton(
                            onClick = onImportNsec,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(stringResource(R.string.main_import_nsec_button))
                        }
                    }
                    if (shareInfo.threshold >= 2u.toUShort()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = onRecoverNsec,
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.error
                            )
                        ) {
                            Text(stringResource(R.string.main_recover_nsec_from_shares))
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    HorizontalDivider()
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = onCreateAccount,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(stringResource(R.string.main_create_account_button))
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = onRecoverMnemonic,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(stringResource(R.string.main_import_from_seed_words_button))
                    }
                }
            }
        } else {
            NoShareCard(
                onImport = onImport,
                onImportNsec = onImportNsec,
                onCreateAccount = onCreateAccount,
                onRecoverMnemonic = onRecoverMnemonic,
                onCreateGroup = onCreateGroup
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

private data class AccountInitial(
    val accounts: List<AccountInfo>,
    val activeKey: String?,
    val relays: List<String>,
    val profileRelays: List<String>
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun BackupPromptCard(onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                stringResource(R.string.main_backup_prompt_title),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                stringResource(R.string.main_backup_prompt_text),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
        }
    }
}

private data class PollResult(
    val hasShare: Boolean,
    val shareInfo: ShareInfo?,
    val allAccounts: List<AccountInfo>,
    val activeAccountKey: String?,
    val descriptorCount: Int,
    val activeDidBackup: Boolean?
)

@Composable
private fun KillSwitchConfirmDialog(
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.main_kill_switch_dialog_title)) },
        text = { Text(stringResource(R.string.main_kill_switch_dialog_text)) },
        confirmButton = {
            TextButton(onClick = onConfirm) { Text(stringResource(R.string.main_enable)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.main_cancel)) }
        }
    )
}

@Composable
private fun PinMismatchDialog(
    hostname: String,
    onClearAndRetry: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.main_pin_mismatch_title)) },
        text = {
            Text(stringResource(R.string.main_pin_mismatch_text, hostname))
        },
        confirmButton = {
            TextButton(onClick = onClearAndRetry) { Text(stringResource(R.string.main_clear_pin_and_retry)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.main_dismiss)) }
        }
    )
}

@Composable
private fun ShareSettingsSection(
    relays: List<String>,
    profileRelays: List<String>,
    certificatePins: List<CertificatePin>,
    proxyEnabled: Boolean,
    proxyPort: Int,
    onAddRelay: (String) -> Unit,
    onRemoveRelay: (String) -> Unit,
    onAddProfileRelay: (String) -> Unit,
    onRemoveProfileRelay: (String) -> Unit,
    onStagePin: (String, String) -> Unit,
    onRetirePin: (String, String) -> Unit,
    onClearAllPins: () -> Unit,
    onProxyActivate: (Int) -> Unit,
    onProxyDeactivate: () -> Unit
) {
    RelaysCard(
        relays = relays,
        onAddRelay = onAddRelay,
        onRemoveRelay = onRemoveRelay,
        profileRelays = profileRelays,
        onAddProfileRelay = onAddProfileRelay,
        onRemoveProfileRelay = onRemoveProfileRelay
    )
    Spacer(modifier = Modifier.height(16.dp))

    CertificatePinsCard(
        pins = certificatePins,
        onStagePin = onStagePin,
        onRetirePin = onRetirePin,
        onClearAllPins = onClearAllPins
    )
    Spacer(modifier = Modifier.height(16.dp))

    TorOrbotCard(
        enabled = proxyEnabled,
        port = proxyPort,
        onActivate = onProxyActivate,
        onDeactivate = onProxyDeactivate
    )
    Spacer(modifier = Modifier.height(16.dp))
}

@Composable
private fun DatabaseManagementSection(
    databaseSizeMb: String,
    onCleanup: () -> Unit
) {
    Text(
        stringResource(R.string.main_database_size_label, databaseSizeMb),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Spacer(modifier = Modifier.height(8.dp))

    OutlinedButton(
        onClick = onCleanup,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(stringResource(R.string.main_cleanup_expired_data))
    }

    Spacer(modifier = Modifier.height(16.dp))

    Text(
        stringResource(R.string.main_version_label, BuildConfig.VERSION_NAME),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Spacer(modifier = Modifier.height(8.dp))
}

@Composable
private fun SettingsFooterLinks() {
    val primaryColor = MaterialTheme.colorScheme.primary
    Text(
        buildAnnotatedString {
            withLink(
                LinkAnnotation.Url(
                    "https://github.com/privkeyio/keep-android",
                    styles = TextLinkStyles(
                        style = SpanStyle(
                            color = primaryColor,
                            textDecoration = TextDecoration.Underline
                        )
                    )
                )
            ) {
                append(stringResource(R.string.main_source_code))
            }
            append("  |  ")
            withLink(
                LinkAnnotation.Url(
                    "https://privkey.io",
                    styles = TextLinkStyles(
                        style = SpanStyle(
                            color = primaryColor,
                            textDecoration = TextDecoration.Underline
                        )
                    )
                )
            ) {
                append(stringResource(R.string.main_support_development))
            }
        },
        style = MaterialTheme.typography.bodySmall,
        textAlign = TextAlign.Center
    )

    Spacer(modifier = Modifier.height(24.dp))
}

private fun getShareAwareCipher(storage: AndroidKeystoreStorage): Cipher? =
    runCatching {
        val key = storage.getActiveShareKey()
        if (key != null) storage.getCipherForShareDecryption(key)
        else storage.getCipherForDecryption()
    }.onFailure {
        if (BuildConfig.DEBUG) Log.e("MainActivity", "Failed to get cipher: ${it::class.simpleName}")
    }.getOrNull()
