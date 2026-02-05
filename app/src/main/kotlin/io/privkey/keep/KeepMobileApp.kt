package io.privkey.keep

import android.app.Application
import android.util.Log
import io.privkey.keep.nip46.BunkerService
import io.privkey.keep.nip55.AutoSigningSafeguards
import io.privkey.keep.nip55.CallerVerificationStore
import io.privkey.keep.nip55.Nip55Database
import io.privkey.keep.nip55.PermissionStore
import io.privkey.keep.service.KeepAliveService
import io.privkey.keep.service.NetworkConnectivityManager
import io.privkey.keep.service.SigningNotificationManager
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.AutoStartStore
import io.privkey.keep.storage.BiometricTimeoutStore
import io.privkey.keep.storage.BunkerConfigStore
import io.privkey.keep.storage.ForegroundServiceStore
import io.privkey.keep.storage.KillSwitchStore
import io.privkey.keep.storage.PinStore
import io.privkey.keep.storage.ProxyConfig
import io.privkey.keep.storage.ProxyConfigStore
import io.privkey.keep.storage.RelayConfigStore
import io.privkey.keep.storage.SignPolicyStore
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.Nip55Handler
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import javax.crypto.Cipher

private const val TAG = "KeepMobileApp"

class KeepMobileApp : Application() {
    private var keepMobile: KeepMobile? = null
    private var storage: AndroidKeystoreStorage? = null
    private var relayConfigStore: RelayConfigStore? = null
    private var killSwitchStore: KillSwitchStore? = null
    private var signPolicyStore: SignPolicyStore? = null
    private var autoStartStore: AutoStartStore? = null
    private var foregroundServiceStore: ForegroundServiceStore? = null
    private var pinStore: PinStore? = null
    private var biometricTimeoutStore: BiometricTimeoutStore? = null
    private var nip55Handler: Nip55Handler? = null
    private var permissionStore: PermissionStore? = null
    private var callerVerificationStore: CallerVerificationStore? = null
    private var autoSigningSafeguards: AutoSigningSafeguards? = null
    private var networkManager: NetworkConnectivityManager? = null
    private var signingNotificationManager: SigningNotificationManager? = null
    private var bunkerConfigStore: BunkerConfigStore? = null
    private var proxyConfigStore: ProxyConfigStore? = null
    private var announceJob: Job? = null
    private var connectionJob: Job? = null
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private val _connectionState = MutableStateFlow(ConnectionState())
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    override fun onCreate() {
        super.onCreate()
        initializeKeepMobile()
        initializePermissionStore()
        initializeNetworkMonitoring()
        initializeForegroundService()
        initializeNotifications()
        initializeBunkerService()
    }

    private fun initializeKeepMobile() {
        runCatching {
            val newStorage = AndroidKeystoreStorage(this)
            val newKeepMobile = KeepMobile(newStorage)
            storage = newStorage
            relayConfigStore = RelayConfigStore(this)
            killSwitchStore = KillSwitchStore(this)
            signPolicyStore = SignPolicyStore(this)
            autoStartStore = AutoStartStore(this)
            foregroundServiceStore = ForegroundServiceStore(this)
            pinStore = PinStore(this)
            biometricTimeoutStore = BiometricTimeoutStore(this)
            proxyConfigStore = ProxyConfigStore(this)
            keepMobile = newKeepMobile
            nip55Handler = Nip55Handler(newKeepMobile)
        }.onFailure { e ->
            if (BuildConfig.DEBUG) Log.e(TAG, "Failed to initialize KeepMobile: ${e::class.simpleName}", e)
        }
    }

    private fun initializeNetworkMonitoring() {
        val autoStartEnabled = autoStartStore?.isEnabled() == true
        val foregroundServiceEnabled = foregroundServiceStore?.isEnabled() == true
        if (autoStartEnabled && !foregroundServiceEnabled) {
            ensureNetworkManagerRegistered()
        }
    }

    private fun initializeForegroundService() {
        if (foregroundServiceStore?.isEnabled() == true) {
            KeepAliveService.start(this)
        }
    }

    private fun initializePermissionStore() {
        try {
            val store = PermissionStore(Nip55Database.getInstance(this))
            permissionStore = store
            callerVerificationStore = CallerVerificationStore(this)
            autoSigningSafeguards = AutoSigningSafeguards(this)
            applicationScope.launch {
                store.cleanupExpired()
                callerVerificationStore?.cleanupExpiredNonces()
            }
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.e(TAG, "Failed to initialize PermissionStore: ${e::class.simpleName}")
        }
    }

    private fun initializeNotifications() {
        runCatching {
            val manager = SigningNotificationManager(this)
            signingNotificationManager = manager
            applicationScope.launch { manager.cleanupStaleEntries() }
        }.onFailure { e ->
            if (BuildConfig.DEBUG) Log.e(TAG, "Failed to initialize SigningNotificationManager: ${e::class.simpleName}", e)
        }
    }

    private fun initializeBunkerService() {
        runCatching {
            val store = BunkerConfigStore(this)
            bunkerConfigStore = store
            if (store.isEnabled()) {
                BunkerService.start(this)
            }
        }.onFailure { e ->
            if (BuildConfig.DEBUG) Log.e(TAG, "Failed to initialize BunkerService: ${e::class.simpleName}", e)
        }
    }

    fun getKeepMobile(): KeepMobile? = keepMobile

    fun getStorage(): AndroidKeystoreStorage? = storage

    fun getRelayConfigStore(): RelayConfigStore? = relayConfigStore

    fun getKillSwitchStore(): KillSwitchStore? = killSwitchStore

    fun getSignPolicyStore(): SignPolicyStore? = signPolicyStore

    fun getAutoStartStore(): AutoStartStore? = autoStartStore

    fun getForegroundServiceStore(): ForegroundServiceStore? = foregroundServiceStore

    fun getPinStore(): PinStore? = pinStore

    fun getBiometricTimeoutStore(): BiometricTimeoutStore? = biometricTimeoutStore

    fun getNip55Handler(): Nip55Handler? = nip55Handler

    fun getPermissionStore(): PermissionStore? = permissionStore

    fun getCallerVerificationStore(): CallerVerificationStore? = callerVerificationStore

    fun getAutoSigningSafeguards(): AutoSigningSafeguards? = autoSigningSafeguards

    fun getSigningNotificationManager(): SigningNotificationManager? = signingNotificationManager

    fun getBunkerConfigStore(): BunkerConfigStore? = bunkerConfigStore

    fun getProxyConfigStore(): ProxyConfigStore? = proxyConfigStore

    fun updateBunkerService(enabled: Boolean) {
        bunkerConfigStore?.setEnabled(enabled)
        val action = if (enabled) BunkerService::start else BunkerService::stop
        action(this)
    }

    fun initializeWithRelays(relays: List<String>) {
        relayConfigStore?.setRelays(relays)
    }

    fun connectWithCipher(cipher: Cipher, onSuccess: () -> Unit, onError: (String) -> Unit) {
        val mobile = keepMobile ?: return onError("KeepMobile not initialized")
        val store = storage ?: return onError("Storage not available")
        val config = relayConfigStore ?: return onError("Relay configuration not available")

        val relays = config.getRelays()
        if (relays.isEmpty()) return onError("No relays configured")

        connectionJob?.cancel()
        _connectionState.value = ConnectionState(isConnecting = true)

        val connectId = UUID.randomUUID().toString()
        connectionJob = applicationScope.launch {
            runCatching {
                store.setPendingCipher(connectId, cipher)
                store.setRequestIdContext(connectId)
                try {
                    initializeConnection(mobile, relays)
                } finally {
                    store.clearRequestIdContext()
                    store.clearPendingCipher(connectId)
                }
                startPeriodicPeerCheck(mobile, config)
            }
                .onSuccess {
                    if (BuildConfig.DEBUG) Log.d(TAG, "Connection successful")
                    _connectionState.value = ConnectionState(isConnected = true)
                    withContext(Dispatchers.Main) { onSuccess() }
                }
                .onFailure { e ->
                    announceJob?.cancel()
                    if (isCancellationException(e)) {
                        _connectionState.value = ConnectionState()
                        return@onFailure
                    }
                    if (BuildConfig.DEBUG) Log.e(TAG, "Failed to connect: ${e::class.simpleName}: ${e.message}", e)
                    _connectionState.value = ConnectionState(error = "Connection failed")
                    withContext(Dispatchers.Main) { onError("Connection failed") }
                }
        }
    }

    private suspend fun initializeConnection(mobile: KeepMobile, relays: List<String>) {
        val proxy = proxyConfigStore?.getProxyConfig()
        if (BuildConfig.DEBUG) {
            val shareInfo = mobile.getShareInfo()
            Log.d(TAG, "Share: index=${shareInfo?.shareIndex}, group=${shareInfo?.groupPubkey?.take(16)}")
            Log.d(TAG, "Initializing with ${relays.size} relay(s), proxy=${proxy != null}")
        }
        initializeWithProxy(mobile, relays, proxy)
        if (BuildConfig.DEBUG) Log.d(TAG, "Initialize completed, peers: ${mobile.getPeers().size}")
    }

    private fun initializeWithProxy(mobile: KeepMobile, relays: List<String>, proxy: ProxyConfig?) {
        if (proxy != null) {
            mobile.initializeWithProxy(relays, proxy.host, proxy.port.toUShort())
        } else {
            mobile.initialize(relays)
        }
    }

    private fun startPeriodicPeerCheck(mobile: KeepMobile, config: RelayConfigStore) {
        announceJob?.cancel()
        announceJob = applicationScope.launch {
            repeat(10) { iteration ->
                delay(5000)
                runCatching {
                    val currentRelays = config.getRelays()
                    if (currentRelays.isEmpty()) {
                        if (BuildConfig.DEBUG) Log.w(TAG, "No relays configured, skipping peer check")
                        return@runCatching
                    }
                    val peers = mobile.getPeers()
                    if (BuildConfig.DEBUG) {
                        Log.d(TAG, "Peer check #${iteration + 1}, peers: ${peers.size}")
                    }
                }.onFailure {
                    if (BuildConfig.DEBUG) Log.e(TAG, "Peer check failed on iteration ${iteration + 1}", it)
                    if (it is CancellationException) throw it
                }
            }
        }
    }

    fun reconnectRelays() {
        val mobile = keepMobile ?: return
        val config = relayConfigStore ?: return
        val store = storage ?: return

        val relays = config.getRelays()
        if (!store.hasShare() || relays.isEmpty()) return

        applicationScope.launch {
            runCatching { initializeWithProxy(mobile, relays, proxyConfigStore?.getProxyConfig()) }
                .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to reconnect relays: ${it::class.simpleName}") }
        }
    }

    fun updateNetworkMonitoring(enabled: Boolean) {
        if (!enabled) {
            networkManager?.unregister()
            return
        }
        if (foregroundServiceStore?.isEnabled() == true) return
        ensureNetworkManagerRegistered()
    }

    fun updateForegroundService(enabled: Boolean) {
        if (enabled) {
            networkManager?.unregister()
            KeepAliveService.start(this)
        } else {
            KeepAliveService.stop(this)
            if (autoStartStore?.isEnabled() == true) {
                ensureNetworkManagerRegistered()
            }
        }
    }

    private fun ensureNetworkManagerRegistered() {
        val manager = networkManager ?: NetworkConnectivityManager(this) { reconnectRelays() }
            .also { networkManager = it }
        manager.register()
    }

    private fun isCancellationException(e: Throwable): Boolean =
        generateSequence(e) { it.cause }
            .take(10)
            .any { it is CancellationException }
}

data class ConnectionState(
    val isConnected: Boolean = false,
    val isConnecting: Boolean = false,
    val error: String? = null
)
