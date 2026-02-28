package io.privkey.keep

import android.app.Application
import android.util.Log
import io.privkey.keep.descriptor.DescriptorSessionManager
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
import io.privkey.keep.storage.ForegroundServiceStore
import io.privkey.keep.storage.KillSwitchStore
import io.privkey.keep.storage.PinStore
import io.privkey.keep.storage.SignPolicyStore
import io.privkey.keep.uniffi.BunkerConfigInfo
import io.privkey.keep.uniffi.KeepLiveState
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.KeepStateCallback
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.ProxyConfigInfo
import io.privkey.keep.uniffi.RelayConfigInfo
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import javax.crypto.Cipher

private const val TAG = "KeepMobileApp"
private const val PIN_MISMATCH_ERROR = "Certificate pin mismatch"

class KeepMobileApp : Application() {
    private var keepMobile: KeepMobile? = null
    private var storage: AndroidKeystoreStorage? = null
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
    private var initError: String? = null
    private var announceJob: Job? = null
    private var connectionJob: Job? = null
    private var reconnectJob: Job? = null
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Volatile
    var liveState: KeepLiveState? = null
        private set

    @Volatile
    private var pinMismatch: PinMismatchInfo? = null

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
            killSwitchStore = KillSwitchStore(this)
            signPolicyStore = SignPolicyStore(this)
            autoStartStore = AutoStartStore(this)
            foregroundServiceStore = ForegroundServiceStore(this)
            pinStore = PinStore(this)
            biometricTimeoutStore = BiometricTimeoutStore(this)
            keepMobile = newKeepMobile
            nip55Handler = Nip55Handler(newKeepMobile)
            newKeepMobile.setStateCallback(object : KeepStateCallback {
                override fun onStateChanged(state: KeepLiveState) {
                    liveState = state
                }
            })
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
            val mobile = keepMobile ?: return
            val config = mobile.getBunkerConfig()
            if (config.enabled) {
                BunkerService.start(this)
            }
        }.onFailure { e ->
            if (BuildConfig.DEBUG) Log.e(TAG, "Failed to initialize BunkerService: ${e::class.simpleName}", e)
        }
    }

    fun getKeepMobile(): KeepMobile? = keepMobile

    fun getStorage(): AndroidKeystoreStorage? = storage

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

    fun getInitError(): String? = initError

    fun getPinMismatch(): PinMismatchInfo? = pinMismatch

    fun updateBunkerService(enabled: Boolean) {
        val mobile = keepMobile ?: return
        runCatching {
            val current = mobile.getBunkerConfig()
            mobile.saveBunkerConfig(BunkerConfigInfo(enabled, current.authorizedClients))
        }.onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to save bunker config: ${it::class.simpleName}") }
        val action = if (enabled) BunkerService::start else BunkerService::stop
        action(this)
    }

    private fun getActiveRelays(): List<String> {
        val mobile = keepMobile ?: return emptyList()
        val activeKey = storage?.getActiveShareKey()
        return runCatching { mobile.getRelayConfig(activeKey).frostRelays }
            .getOrDefault(emptyList())
    }

    suspend fun initializeWithRelays(relays: List<String>) {
        val mobile = keepMobile ?: return
        val activeKey = storage?.getActiveShareKey()
        val existing = runCatching { mobile.getRelayConfig(activeKey) }.getOrNull()
            ?: RelayConfigInfo(emptyList(), emptyList(), emptyList())
        withContext(Dispatchers.IO) {
            mobile.saveRelayConfig(activeKey, RelayConfigInfo(relays, existing.profileRelays, existing.bunkerRelays))
        }
    }

    fun connectWithCipher(cipher: Cipher, onSuccess: () -> Unit, onError: (String) -> Unit) {
        val mobile = keepMobile ?: return onError("KeepMobile not initialized")
        val store = storage ?: return onError("Storage not available")

        val relays = getActiveRelays()
        if (relays.isEmpty()) return onError("No relays configured")

        connectionJob?.cancel()
        reconnectJob?.cancel()
        pinMismatch = null

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
                    withContext(Dispatchers.Main) { onSuccess() }
                }
                .onFailure { e ->
                    announceJob?.cancel()
                    if (isCancellationException(e)) return@onFailure
                    if (BuildConfig.DEBUG) Log.e(TAG, "Failed to connect: ${e::class.simpleName}")
                    val pm = findPinMismatch(e)
                    pinMismatch = pm
                    val errorMsg = pm?.let { PIN_MISMATCH_ERROR } ?: "Connection failed"
                    withContext(Dispatchers.Main) { onError(errorMsg) }
                }
        }
    }

    private suspend fun initializeConnection(mobile: KeepMobile, relays: List<String>) {
        val proxyConfig = runCatching { mobile.getProxyConfig() }.getOrNull()
        if (BuildConfig.DEBUG) {
            val shareInfo = mobile.getShareInfo()
            Log.d(TAG, "Share: index=${shareInfo?.shareIndex}, hasGroup=${shareInfo?.groupPubkey != null}")
            Log.d(TAG, "Initializing with ${relays.size} relay(s), proxy=${proxyConfig?.enabled == true}")
        }
        if (proxyConfig != null && proxyConfig.enabled && proxyConfig.port.toInt() in 1..65535) {
            mobile.initializeWithProxy(relays, "127.0.0.1", proxyConfig.port)
        } else {
            mobile.initialize(relays)
        }
        if (BuildConfig.DEBUG) Log.d(TAG, "Initialize completed, peers: ${mobile.getPeers().size}")
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
        pinMismatch = null
        BunkerService.stop(this)
        runCatching {
            val current = keepMobile?.getBunkerConfig()
            keepMobile?.saveBunkerConfig(BunkerConfigInfo(false, current?.authorizedClients ?: emptyList()))
        }
        DescriptorSessionManager.clearAll()
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
        pinMismatch = null

        reconnectJob = applicationScope.launch {
            runCatching { initializeConnection(mobile, relays) }
                .onSuccess {
                    if (BuildConfig.DEBUG) Log.d(TAG, "Reconnection successful")
                    startPeriodicPeerCheck(mobile)
                }
                .onFailure { e ->
                    if (isCancellationException(e)) return@onFailure
                    if (BuildConfig.DEBUG) Log.e(TAG, "Failed to reconnect relays: ${e::class.simpleName}")
                    val pm = findPinMismatch(e)
                    pinMismatch = pm
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
        runCatching { keepMobile?.clearCertificatePin(hostname) }
            .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to clearCertificatePin: ${it::class.simpleName}") }
    }

    fun clearAllCertificatePins() {
        runCatching { keepMobile?.clearCertificatePins() }
            .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to clearCertificatePins: ${it::class.simpleName}") }
    }

    fun dismissPinMismatch() {
        pinMismatch = null
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
