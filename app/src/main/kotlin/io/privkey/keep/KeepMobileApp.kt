package io.privkey.keep

import android.app.Application
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.privkey.keep.descriptor.DescriptorSessionManager
import io.privkey.keep.nip46.BunkerConfigStore
import io.privkey.keep.nip46.BunkerService
import io.privkey.keep.nip55.AutoSigningSafeguards
import io.privkey.keep.nip55.CallerVerificationStore
import io.privkey.keep.nip55.EventLogCategory
import io.privkey.keep.nip55.EventLogLevel
import io.privkey.keep.nip55.EventLogStore
import io.privkey.keep.nip55.Nip55Database
import io.privkey.keep.nip55.PermissionStore
import io.privkey.keep.service.KeepAliveService
import io.privkey.keep.service.NetworkConnectivityManager
import io.privkey.keep.service.SigningNotificationManager
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.AndroidSigningAuditStorage
import io.privkey.keep.storage.AutoStartStore
import io.privkey.keep.storage.BiometricTimeoutStore
import io.privkey.keep.storage.ForegroundServiceStore
import io.privkey.keep.storage.KillSwitchStore
import io.privkey.keep.storage.PinStore
import io.privkey.keep.storage.SignPolicyStore
import io.privkey.keep.uniffi.BunkerConfigInfo
import io.privkey.keep.uniffi.ConnectionStatus
import io.privkey.keep.uniffi.KeepLiveState
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.KeepStateCallback
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.PeerStatus
import io.privkey.keep.uniffi.ProxyConfigInfo
import io.privkey.keep.uniffi.RelayConfigInfo
import io.privkey.keep.uniffi.SigningAuditLog
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.UUID
import javax.crypto.Cipher

private const val TAG = "KeepMobileApp"
private const val EVENT_LOG_MAX_AGE_MS = 7L * 24 * 60 * 60 * 1000

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
    private var signingAuditLog: SigningAuditLog? = null
    private var eventLogStore: EventLogStore? = null
    private var networkManager: NetworkConnectivityManager? = null
    private var signingNotificationManager: SigningNotificationManager? = null
    private var initError: String? = null
    private var connectionJob: Job? = null
    private var reconnectJob: Job? = null
    private val initMutex = Mutex()
    private val initDispatcher = Dispatchers.IO.limitedParallelism(1)
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val bunkerToggleDispatcher = Dispatchers.Default.limitedParallelism(1)
    private val mainHandler = Handler(Looper.getMainLooper())

    var liveState: KeepLiveState? by mutableStateOf(null)
        private set

    @Volatile
    private var pinMismatch: PinMismatchInfo? = null

    @Volatile
    private var killSwitchMigrationFailed: Boolean = false

    // Activity-log dedup state. Read/written only inside the state-callback's
    // mainHandler.post block, so it is effectively single-threaded.
    private var lastConnStatusKey: String? = null
    private val lastPeerStatus = HashMap<UShort, PeerStatus>()

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
            migrateKillSwitch(newKeepMobile)
            nip55Handler = Nip55Handler(newKeepMobile)
            newKeepMobile.setStateCallback(object : KeepStateCallback {
                override fun onStateChanged(state: KeepLiveState) {
                    mainHandler.post {
                        liveState = state
                        io.privkey.keep.service.CosignNotifier.update(
                            applicationContext,
                            state.pendingRequests,
                        )
                        captureActivityEvents(state)
                    }
                }
            })
        }.onFailure { e ->
            initError = getString(R.string.keep_mobile_init_failed_error)
            if (BuildConfig.DEBUG) Log.e(TAG, "Failed to initialize KeepMobile: ${e::class.simpleName}", e)
        }
    }

    // Called only on the main thread (from the state callback's mainHandler.post),
    // so the dedup fields need no synchronization. Logs relay status only on
    // transitions and peers only on per-share status changes; the first callback
    // seeds state without emitting to avoid a startup burst.
    private fun captureActivityEvents(state: KeepLiveState) {
        val statusKey = connectionStatusKey(state.connectionStatus)
        if (statusKey != lastConnStatusKey) {
            val previous = lastConnStatusKey
            lastConnStatusKey = statusKey
            if (previous != null || state.connectionStatus !is ConnectionStatus.Disconnected) {
                val (level, source, message) = connectionEventDetails(state.connectionStatus)
                logActivityEvent(EventLogCategory.RELAY, level, source, message)
            }
        }

        val seeded = lastPeerStatus.isNotEmpty()
        for (peer in state.peers) {
            val prev = lastPeerStatus[peer.shareIndex]
            if (prev != peer.status) {
                lastPeerStatus[peer.shareIndex] = peer.status
                if (seeded || prev != null) {
                    val label = peer.name?.takeIf { it.isNotBlank() } ?: "share #${peer.shareIndex}"
                    val level = if (peer.status == PeerStatus.OFFLINE) EventLogLevel.WARN else EventLogLevel.INFO
                    logActivityEvent(EventLogCategory.PEER, level, label, "peer ${peer.status.name.lowercase()}")
                }
            }
        }
    }

    private fun connectionStatusKey(status: ConnectionStatus): String = when (status) {
        is ConnectionStatus.Disconnected -> "disconnected"
        is ConnectionStatus.Connecting -> "connecting"
        is ConnectionStatus.Connected -> "connected"
        is ConnectionStatus.Error -> "error:${status.message}"
    }

    private fun connectionEventDetails(status: ConnectionStatus): Triple<EventLogLevel, String, String> = when (status) {
        is ConnectionStatus.Disconnected -> Triple(EventLogLevel.WARN, "", "disconnected")
        is ConnectionStatus.Connecting -> Triple(EventLogLevel.INFO, "", "connecting")
        is ConnectionStatus.Connected -> Triple(EventLogLevel.INFO, "", "connected")
        is ConnectionStatus.Error -> Triple(EventLogLevel.ERROR, "", status.message)
    }

    private fun logActivityEvent(category: EventLogCategory, level: EventLogLevel, source: String, message: String) {
        val store = eventLogStore ?: return
        applicationScope.launch {
            runCatching { store.log(category, level, source, message) }
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
            val db = Nip55Database.getInstance(this)
            val store = PermissionStore(db)
            permissionStore = store
            callerVerificationStore = CallerVerificationStore(this)
            autoSigningSafeguards = AutoSigningSafeguards(this)
            val eventLog = EventLogStore.getInstance(db)
            eventLogStore = eventLog
            initializeSigningAuditLog(db)
            applicationScope.launch {
                store.cleanupExpired()
                callerVerificationStore?.cleanupExpiredNonces()
                runCatching {
                    eventLog.cleanupOld(System.currentTimeMillis() - EVENT_LOG_MAX_AGE_MS)
                }
            }
        }.onFailure { e ->
            if (BuildConfig.DEBUG) Log.e(TAG, "Failed to initialize PermissionStore: ${e::class.simpleName}")
        }
    }

    private fun initializeSigningAuditLog(db: Nip55Database) {
        runCatching {
            val storage = AndroidSigningAuditStorage(db.auditLogDao())
            signingAuditLog = SigningAuditLog(storage)
        }.onFailure { e ->
            Log.e(TAG, "Failed to initialize SigningAuditLog: ${e::class.simpleName}")
            initError = getString(R.string.keep_mobile_audit_log_unavailable_error)
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

    fun isSigningKilled(): Boolean {
        if (killSwitchMigrationFailed) return true
        val mobile = getKeepMobile() ?: return true
        return runCatching { mobile.getKillSwitch() }
            .onFailure { Log.e(TAG, "Kill switch read failed, failing closed: ${it::class.simpleName}") }
            .getOrDefault(true)
    }

    // Transfer the legacy SharedPreferences kill-switch state into the Rust core
    // exactly once, at startup before any signing gate or FROST round can run, so a
    // previously engaged kill switch survives an upgrade. Failure to read or write
    // leaves the store un-migrated so it retries; it never marks migrated on failure.
    // On failure the session fails closed: the core kill switch is engaged so signing
    // cannot resume, because the legacy state could not be confirmed disengaged.
    private fun migrateKillSwitch(mobile: KeepMobile) {
        val store = killSwitchStore ?: return
        val migrated = runCatching { store.hasMigrated() }
        if (migrated.getOrNull() == true) return
        runCatching {
            migrated.getOrThrow()
            if (store.legacyEnabled()) {
                mobile.setKillSwitch(true)
            }
            store.markMigrated()
        }.onFailure { e ->
            if (BuildConfig.DEBUG) Log.e(TAG, "Kill switch migration failed: ${e::class.simpleName}", e)
            if (runCatching { mobile.setKillSwitch(true) }.isFailure) {
                killSwitchMigrationFailed = true
            }
        }
    }

    fun getSignPolicyStore(): SignPolicyStore? = signPolicyStore

    fun getAutoStartStore(): AutoStartStore? = autoStartStore

    fun getForegroundServiceStore(): ForegroundServiceStore? = foregroundServiceStore

    fun getPinStore(): PinStore? = pinStore

    fun getBiometricTimeoutStore(): BiometricTimeoutStore? = biometricTimeoutStore

    fun getNip55Handler(): Nip55Handler? = nip55Handler

    fun getPermissionStore(): PermissionStore? = permissionStore

    fun getCallerVerificationStore(): CallerVerificationStore? = callerVerificationStore

    fun getAutoSigningSafeguards(): AutoSigningSafeguards? = autoSigningSafeguards

    fun getSigningAuditLog(): SigningAuditLog? = signingAuditLog

    fun getEventLogStore(): EventLogStore? = eventLogStore

    fun getSigningNotificationManager(): SigningNotificationManager? = signingNotificationManager

    fun getInitError(): String? = initError

    fun getPinMismatch(): PinMismatchInfo? = pinMismatch

    fun updateBunkerService(enabled: Boolean) {
        val mobile = keepMobile ?: return
        applicationScope.launch(bunkerToggleDispatcher) {
            BunkerConfigStore.withLock {
                runCatching {
                    val current = mobile.getBunkerConfig()
                    mobile.saveBunkerConfig(BunkerConfigInfo(enabled, current.authorizedClients))
                }.onFailure {
                    if (BuildConfig.DEBUG) Log.e(TAG, "Failed to save bunker config: ${it::class.simpleName}")
                    return@withLock
                }
                val action = if (enabled) BunkerService::start else BunkerService::stop
                action(this@KeepMobileApp)
            }
        }
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

    suspend fun ensureInitialized(requestId: String? = null) {
        val mobile = keepMobile
            ?: throw IllegalStateException("KeepMobile not initialized")
        initMutex.withLock {
            if (liveState != null && mobile.getShareInfo() != null) return

            val relays = getActiveRelays().ifEmpty {
                listOf("wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net")
            }
            val store = storage
            withContext(initDispatcher) {
                if (requestId != null && store != null) {
                    store.setRequestIdContext(requestId)
                }
                try {
                    initializeConnection(mobile, relays)
                } finally {
                    if (requestId != null && store != null) {
                        store.clearRequestIdContext()
                    }
                }
            }
        }
    }

    fun connectWithCipher(cipher: Cipher, onSuccess: () -> Unit, onError: (String) -> Unit) {
        val mobile = keepMobile ?: return onError(getString(R.string.keep_mobile_not_initialized_error))
        val store = storage ?: return onError(getString(R.string.keep_mobile_storage_unavailable_error))

        val relays = getActiveRelays()
        if (relays.isEmpty()) return onError(getString(R.string.keep_mobile_no_relays_error))

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
            }
                .onSuccess {
                    if (BuildConfig.DEBUG) Log.d(TAG, "Connection successful")
                    withContext(Dispatchers.Main) { onSuccess() }
                }
                .onFailure { e ->
                    if (isCancellationException(e)) return@onFailure
                    if (BuildConfig.DEBUG) Log.e(TAG, "Failed to connect: ${e::class.simpleName}")
                    pinMismatch = findPinMismatch(e)
                    val errorMsg = if (pinMismatch != null) {
                        getString(R.string.certificate_pin_mismatch_error)
                    } else {
                        getString(R.string.connection_failed_error)
                    }
                    withContext(Dispatchers.Main) { onError(errorMsg) }
                }
        }
    }

    private suspend fun initializeConnection(mobile: KeepMobile, relays: List<String>) {
        val proxyConfig = runCatching { mobile.getProxyConfig() }.getOrNull()
        if (BuildConfig.DEBUG) {
            Log.d(TAG, "Initializing with ${relays.size} relay(s), proxy=${proxyConfig?.enabled == true}")
        }
        if (proxyConfig != null && proxyConfig.enabled && proxyConfig.port.toInt() in 1..65535) {
            mobile.initializeWithProxy(relays, "127.0.0.1", proxyConfig.port)
        } else {
            mobile.initialize(relays)
        }
        if (BuildConfig.DEBUG) Log.d(TAG, "Initialize completed, peers: ${mobile.getPeers().size}")
    }

    suspend fun onAccountSwitched() {
        connectionJob?.cancel()
        reconnectJob?.cancel()
        pinMismatch = null
        BunkerService.stop(this)
        keepMobile?.let { mobile ->
            runCatching {
                BunkerConfigStore.update(mobile) { current ->
                    BunkerConfigInfo(false, current.authorizedClients)
                }
            }
        }
        DescriptorSessionManager.clearAll()
        withContext(Dispatchers.IO) {
            runAccountSwitchCleanup("revoke permissions") { permissionStore?.revokeAllPermissions() }
            runAccountSwitchCleanup("clear app settings") { permissionStore?.clearAllAppSettings() }
            runAccountSwitchCleanup("clear velocity") { permissionStore?.clearAllVelocity() }
            runAccountSwitchCleanup("clear caller trust") { callerVerificationStore?.clearAllTrust() }
            runAccountSwitchCleanup("clear auto-signing state") { autoSigningSafeguards?.clearAll() }
            runAccountSwitchCleanup("clear signing audit log") { permissionStore?.clearAuditLog() }
            runAccountSwitchCleanup("clear activity log") { eventLogStore?.clear() }
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
                }
                .onFailure { e ->
                    if (isCancellationException(e)) return@onFailure
                    if (BuildConfig.DEBUG) Log.e(TAG, "Failed to reconnect relays: ${e::class.simpleName}")
                    pinMismatch = findPinMismatch(e)
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
