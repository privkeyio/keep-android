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
import io.privkey.keep.storage.ProfileRelayConfigStore
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
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import javax.crypto.Cipher

private const val TAG = "KeepMobileApp"
private const val PIN_MISMATCH_ERROR = "Certificate pin mismatch"

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
    private var profileRelayConfigStore: ProfileRelayConfigStore? = null
    private var initError: String? = null
    private var announceJob: Job? = null
    private var connectionJob: Job? = null
    private var reconnectJob: Job? = null
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
            runCatching { newStorage.migrateLegacyShareToRegistrySync() }
                .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Legacy migration failed: ${it::class.simpleName}", it) }
            val newKeepMobile = KeepMobile(newStorage)
            storage = newStorage
            relayConfigStore = RelayConfigStore(this)
            killSwitchStore = KillSwitchStore(this)
            signPolicyStore = SignPolicyStore(this)
            autoStartStore = AutoStartStore(this)
            foregroundServiceStore = ForegroundServiceStore(this)
            pinStore = PinStore(this)
            biometricTimeoutStore = BiometricTimeoutStore(this)
            runCatching { proxyConfigStore = ProxyConfigStore(this) }
                .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to initialize ProxyConfigStore: ${it::class.simpleName}") }
            runCatching { profileRelayConfigStore = ProfileRelayConfigStore(this) }
                .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to initialize ProfileRelayConfigStore: ${it::class.simpleName}") }
            keepMobile = newKeepMobile
            nip55Handler = Nip55Handler(newKeepMobile)
        }.onFailure { e ->
            initError = "Failed to initialize application"
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
        runCatching {
            val store = PermissionStore(Nip55Database.getInstance(this))
            permissionStore = store
            callerVerificationStore = CallerVerificationStore(this)
            autoSigningSafeguards = AutoSigningSafeguards(this)
            applicationScope.launch {
                store.cleanupExpired()
                callerVerificationStore?.cleanupExpiredNonces()
            }
        }.onFailure { e ->
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

    fun getProfileRelayConfigStore(): ProfileRelayConfigStore? = profileRelayConfigStore

    fun getInitError(): String? = initError

    fun updateBunkerService(enabled: Boolean) {
        bunkerConfigStore?.setEnabled(enabled)
        val action = if (enabled) BunkerService::start else BunkerService::stop
        action(this)
    }

    private fun getActiveRelays(): List<String> {
        val config = relayConfigStore ?: return emptyList()
        val activeKey = storage?.getActiveShareKey()
        return if (activeKey != null) config.getRelaysForAccount(activeKey) else config.getRelays()
    }

    suspend fun initializeWithRelays(relays: List<String>) {
        val activeKey = storage?.getActiveShareKey()
        if (activeKey != null) {
            relayConfigStore?.setRelaysForAccount(activeKey, relays)
        } else {
            relayConfigStore?.setRelays(relays)
        }
    }

    fun connectWithCipher(cipher: Cipher, onSuccess: () -> Unit, onError: (String) -> Unit) {
        val mobile = keepMobile ?: return onError("KeepMobile not initialized")
        val store = storage ?: return onError("Storage not available")

        val relays = getActiveRelays()
        if (relays.isEmpty()) return onError("No relays configured")

        connectionJob?.cancel()
        reconnectJob?.cancel()
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
                startPeriodicPeerCheck(mobile)
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
                    val pinMismatch = findPinMismatch(e)
                    val errorMsg = pinMismatch?.let { PIN_MISMATCH_ERROR } ?: "Connection failed"
                    _connectionState.value = ConnectionState(error = errorMsg, pinMismatch = pinMismatch)
                    withContext(Dispatchers.Main) { onError(errorMsg) }
                }
        }
    }

    private suspend fun initializeConnection(mobile: KeepMobile, relays: List<String>) {
        val proxy = proxyConfigStore?.getProxyConfig()
        if (BuildConfig.DEBUG) {
            val shareInfo = mobile.getShareInfo()
            Log.d(TAG, "Share: index=${shareInfo?.shareIndex}, hasGroup=${shareInfo?.groupPubkey != null}")
            Log.d(TAG, "Initializing with ${relays.size} relay(s), proxy=${proxy != null}")
        }
        initializeWithProxy(mobile, relays, proxy)
        if (BuildConfig.DEBUG) Log.d(TAG, "Initialize completed, peers: ${mobile.getPeers().size}")
    }

    private fun initializeWithProxy(mobile: KeepMobile, relays: List<String>, proxy: ProxyConfig?) {
        if (proxy != null && proxy.port in 1..65535 && hasProxySupport(mobile)) {
            invokeInitializeWithProxy(mobile, relays, proxy.host, proxy.port.toUShort())
        } else {
            mobile.initialize(relays)
        }
    }

    private fun hasProxySupport(mobile: KeepMobile): Boolean = runCatching {
        mobile.javaClass.methods.any { it.name == "initializeWithProxy" }
    }.getOrDefault(false)

    private fun invokeInitializeWithProxy(
        mobile: KeepMobile,
        relays: List<String>,
        proxyHost: String,
        proxyPort: UShort
    ) {
        val method = mobile.javaClass.methods.first { it.name == "initializeWithProxy" }
        method.invoke(mobile, relays, proxyHost, proxyPort)
    }

    private fun startPeriodicPeerCheck(mobile: KeepMobile) {
        announceJob?.cancel()
        announceJob = applicationScope.launch {
            repeat(10) { iteration ->
                delay(5000)
                runCatching {
                    val currentRelays = getActiveRelays()
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

    suspend fun onAccountSwitched() {
        connectionJob?.cancel()
        reconnectJob?.cancel()
        announceJob?.cancel()
        _connectionState.value = ConnectionState()
        BunkerService.stop(this)
        bunkerConfigStore?.setEnabled(false)
        withContext(Dispatchers.IO) {
            runAccountSwitchCleanup("revoke permissions") { permissionStore?.revokeAllPermissions() }
            runAccountSwitchCleanup("clear app settings") { permissionStore?.clearAllAppSettings() }
            runAccountSwitchCleanup("clear velocity") { permissionStore?.clearAllVelocity() }
            runAccountSwitchCleanup("clear caller trust") { callerVerificationStore?.clearAllTrust() }
            runAccountSwitchCleanup("clear auto-signing state") { autoSigningSafeguards?.clearAll() }
        }
    }

    private suspend fun runAccountSwitchCleanup(label: String, action: suspend () -> Unit) {
        runCatching { action() }
            .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to $label on account switch", it) }
    }

    fun reconnectRelays() {
        val mobile = keepMobile ?: return
        val store = storage ?: return
        val relays = getActiveRelays()
        if (!store.hasShare() || relays.isEmpty()) return

        reconnectJob?.cancel()
        connectionJob?.cancel()
        _connectionState.value = ConnectionState(isConnecting = true)

        reconnectJob = applicationScope.launch {
            runCatching { initializeWithProxy(mobile, relays, proxyConfigStore?.getProxyConfig()) }
                .onSuccess {
                    if (BuildConfig.DEBUG) Log.d(TAG, "Reconnection successful")
                    _connectionState.value = ConnectionState(isConnected = true)
                    startPeriodicPeerCheck(mobile)
                }
                .onFailure { e ->
                    if (isCancellationException(e)) {
                        _connectionState.value = ConnectionState()
                        return@onFailure
                    }
                    if (BuildConfig.DEBUG) Log.e(TAG, "Failed to reconnect relays: ${e::class.simpleName}")
                    val pinMismatch = findPinMismatch(e)
                    val errorMsg = pinMismatch?.let { PIN_MISMATCH_ERROR } ?: "Reconnection failed"
                    _connectionState.value = ConnectionState(error = errorMsg, pinMismatch = pinMismatch)
                }
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

    fun clearCertificatePin(hostname: String) {
        invokeKeepMobileMethod("clearCertificatePin", hostname)
    }

    fun clearAllCertificatePins() {
        invokeKeepMobileMethod("clearCertificatePins")
    }

    private fun invokeKeepMobileMethod(name: String, vararg args: Any) {
        runCatching {
            val mobile = keepMobile ?: return
            val method = mobile.javaClass.methods.firstOrNull { it.name == name } ?: return
            method.invoke(mobile, *args)
        }.onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to invoke $name: ${it::class.simpleName}") }
    }

    fun dismissPinMismatch() {
        _connectionState.update { it.copy(error = null, pinMismatch = null) }
    }

    private fun findPinMismatch(e: Throwable): PinMismatchInfo? =
        generateSequence(e) { it.cause }
            .take(10)
            .firstOrNull { it::class.simpleName == "CertificatePinMismatch" }
            ?.let { mismatch ->
                runCatching {
                    val cls = mismatch::class.java
                    val hostname = cls.getMethod("getHostname").invoke(mismatch) as? String ?: return@runCatching null
                    val expected = cls.getMethod("getExpected").invoke(mismatch) as? String ?: return@runCatching null
                    val actual = cls.getMethod("getActual").invoke(mismatch) as? String ?: return@runCatching null
                    PinMismatchInfo(hostname, expected, actual)
                }.getOrNull()
            }

    private fun isCancellationException(e: Throwable): Boolean =
        generateSequence(e) { it.cause }
            .take(10)
            .any { it is CancellationException }
}

data class ConnectionState(
    val isConnected: Boolean = false,
    val isConnecting: Boolean = false,
    val error: String? = null,
    val pinMismatch: PinMismatchInfo? = null
)

data class PinMismatchInfo(
    val hostname: String,
    val expected: String,
    val actual: String
) {
    override fun toString(): String = "PinMismatchInfo(hostname=$hostname)"
}
