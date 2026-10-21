package io.privkey.keep

import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.privkey.keep.descriptor.DescriptorSessionManager
import io.privkey.keep.nip46.BunkerConfigStore
import io.privkey.keep.nip46.BunkerService
import io.privkey.keep.nip55.AUDIT_OP_ACCOUNT_SWITCH
import io.privkey.keep.nip55.AndroidSigningRateLimiterStorage
import io.privkey.keep.nip55.AppSignPolicyOverrides
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
import io.privkey.keep.storage.carryKillSwitch
import io.privkey.keep.storage.OnboardingStore
import io.privkey.keep.storage.PinStore
import io.privkey.keep.storage.RelayAuthWhitelistStore
import io.privkey.keep.storage.SignPolicySelectionPrefs
import io.privkey.keep.uniffi.BunkerConfigInfo
import io.privkey.keep.uniffi.ConnectionStatus
import io.privkey.keep.uniffi.KeepLiveState
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.KeepStateCallback
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.PeerStatus
import io.privkey.keep.uniffi.ProxyConfigInfo
import io.privkey.keep.uniffi.RelayConfigInfo
import io.privkey.keep.uniffi.SignPolicyStore
import io.privkey.keep.uniffi.SigningAuditLog
import io.privkey.keep.uniffi.SigningRateLimiter
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
    // Volatile: written on the main thread during onCreate and read from binder
    // threads, where the signing gates consult it.
    @Volatile
    private var keepMobile: KeepMobile? = null
    private var storage: AndroidKeystoreStorage? = null
    private var killSwitchStore: KillSwitchStore? = null
    private var signPolicyStore: SignPolicyStore? = null
    private var relayAuthWhitelistStore: RelayAuthWhitelistStore? = null
    private var autoStartStore: AutoStartStore? = null
    private var foregroundServiceStore: ForegroundServiceStore? = null
    private var pinStore: PinStore? = null
    private var biometricTimeoutStore: BiometricTimeoutStore? = null
    private var onboardingStore: OnboardingStore? = null
    // Volatile for the same reason as keepMobile: the provider's gate reads it on
    // a binder thread, and it is what incidentally refuses requests that arrive
    // while onCreate is still running.
    @Volatile
    private var nip55Handler: Nip55Handler? = null
    private var permissionStore: PermissionStore? = null
    private var callerVerificationStore: CallerVerificationStore? = null
    private var autoSigningSafeguards: AutoSigningSafeguards? = null
    private var signingRateLimiter: SigningRateLimiter? = null
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
    private val liveNode = LiveNodeTracker()

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
            signPolicyStore = SignPolicyStore(SignPolicySelectionPrefs(this))
            relayAuthWhitelistStore = RelayAuthWhitelistStore(this)
            autoStartStore = AutoStartStore(this)
            foregroundServiceStore = ForegroundServiceStore(this)
            pinStore = PinStore(this)
            biometricTimeoutStore = BiometricTimeoutStore(this)
            onboardingStore = OnboardingStore(this)
            // Carried before the instance is published, not after: content providers
            // are installed before Application.onCreate, so a binder thread reaching
            // isSigningKilled() while this runs would otherwise see a non-null core
            // that has not been told about an engaged legacy switch yet.
            migrateKillSwitch(newKeepMobile)
            keepMobile = newKeepMobile
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
            signingRateLimiter = SigningRateLimiter(AndroidSigningRateLimiterStorage(this))
            val eventLog = EventLogStore.getInstance(db)
            eventLogStore = eventLog
            initializeSigningAuditLog(db)
            applicationScope.launch {
                store.cleanupExpired(signPolicyStore, autoSigningSafeguards)
                // After the expiry sweep, so a row that just aged out is not copied
                // into the core (which has no expiry) as a permanent override. The
                // one-shot gating lives in the migration itself.
                signPolicyStore?.let { policyStore ->
                    AppSignPolicyOverrides.migrateLegacyOverrides(
                        policyStore,
                        store,
                        getSharedPreferences(
                            SignPolicySelectionPrefs.MARKER_PREFS_NAME,
                            Context.MODE_PRIVATE
                        )
                    )
                }
                callerVerificationStore?.cleanupExpiredNonces()
                runCatching {
                    eventLog.cleanupOld(System.currentTimeMillis() - EVENT_LOG_MAX_AGE_MS)
                }
            }
        }.onFailure { e ->
            if (BuildConfig.DEBUG) Log.e(TAG, "Failed to initialize PermissionStore: ${e::class.simpleName}")
            initError = getString(R.string.keep_mobile_permission_store_unavailable_error)
        }
    }

    private fun initializeSigningAuditLog(db: Nip55Database) {
        runCatching {
            val storage = AndroidSigningAuditStorage(db)
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
    // previously engaged kill switch survives an upgrade. A state that cannot be read
    // is carried as engaged rather than as disengaged, so signing never resumes on a
    // restriction that was never seen.
    //
    // A read fault is classified rather than raised, so it takes the ordinary path:
    // the restriction goes into the core, where the user can see it and clear it
    // behind an auth factor, and the carry is retired so it cannot re-apply itself
    // on a later launch. Only a fault outside that classification reaches the
    // handler below, which leaves the store un-migrated and engages on the way out;
    // only an engage that itself fails falls back to killSwitchMigrationFailed,
    // which no authenticated disengage can clear.
    private fun migrateKillSwitch(mobile: KeepMobile) {
        val store = killSwitchStore ?: return
        val migrated = runCatching { store.hasMigrated() }
        if (migrated.getOrNull() == true) return
        runCatching {
            migrated.getOrThrow()
            carryKillSwitch(
                legacy = store.legacyState(),
                engage = { mobile.setKillSwitch(true) },
                retire = { store.markMigrated() },
            )
        }.onFailure { e ->
            if (BuildConfig.DEBUG) Log.e(TAG, "Kill switch migration failed: ${e::class.simpleName}", e)
            if (runCatching { mobile.setKillSwitch(true) }.isFailure) {
                killSwitchMigrationFailed = true
            }
        }
    }

    fun getSignPolicyStore(): SignPolicyStore? = signPolicyStore

    fun getRelayAuthWhitelistStore(): RelayAuthWhitelistStore? = relayAuthWhitelistStore

    fun getAutoStartStore(): AutoStartStore? = autoStartStore

    fun getForegroundServiceStore(): ForegroundServiceStore? = foregroundServiceStore

    fun getPinStore(): PinStore? = pinStore

    fun getBiometricTimeoutStore(): BiometricTimeoutStore? = biometricTimeoutStore

    fun getOnboardingStore(): OnboardingStore? = onboardingStore

    fun getNip55Handler(): Nip55Handler? = nip55Handler

    fun getPermissionStore(): PermissionStore? = permissionStore

    fun getCallerVerificationStore(): CallerVerificationStore? = callerVerificationStore

    fun getAutoSigningSafeguards(): AutoSigningSafeguards? = autoSigningSafeguards

    fun getSigningRateLimiter(): SigningRateLimiter? = signingRateLimiter

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
            if (isNodeLive() && mobile.getShareInfo() != null) return

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
        val startedAt = liveNode.beginInit()
        val proxyConfig = runCatching { mobile.getProxyConfig() }.getOrNull()
        if (BuildConfig.DEBUG) {
            Log.d(TAG, "Initializing with ${relays.size} relay(s), proxy=${proxyConfig?.enabled == true}")
        }
        if (proxyConfig != null && proxyConfig.enabled && proxyConfig.port.toInt() in 1..65535) {
            mobile.initializeWithProxy(relays, "127.0.0.1", proxyConfig.port)
        } else {
            mobile.initialize(relays)
        }
        liveNode.built(startedAt)
        if (BuildConfig.DEBUG) Log.d(TAG, "Initialize completed, peers: ${mobile.getPeers().size}")
    }

    @androidx.annotation.VisibleForTesting
    internal var resetBunkerForSwitch: suspend (Context, KeepMobile) -> Boolean =
        { context, mobile -> BunkerService.resetForAccountSwitch(context, mobile) }

    /**
     * Clears the previous account's state. Returns false when the bunker's revoke-all mark
     * could not be saved. With [stopIfBunkerResetFails] it then stops before wiping anything,
     * and the caller must not change the account: the bunker's clients would act as the new one.
     */
    suspend fun onAccountSwitched(stopIfBunkerResetFails: Boolean = false): Boolean {
        BunkerService.stop(this)
        var bunkerResetFailed = false
        var bunkerResetComplete = true
        withContext(Dispatchers.IO) {
            // First: the bunker's clients belong to the previous account; also turns it off.
            runAccountSwitchCleanup("reset bunker clients") {
                try {
                    keepMobile?.let { bunkerResetComplete = resetBunkerForSwitch(this@KeepMobileApp, it) }
                } catch (e: Exception) {
                    if (e !is CancellationException) bunkerResetFailed = true
                    throw e
                }
            }
        }
        if (bunkerResetFailed && stopIfBunkerResetFails) {
            withContext(Dispatchers.IO) {
                runAccountSwitchCleanup("record bunker reset failure") {
                    eventLogStore?.log(
                        EventLogCategory.BUNKER, EventLogLevel.ERROR, "bunker",
                        "The bunker was stopped and could not be reset, so the account was not changed; its clients may need pairing again. Try again"
                    )
                }
            }
            return false
        }
        connectionJob?.cancel()
        reconnectJob?.cancel()
        pinMismatch = null
        DescriptorSessionManager.clearAll()
        withContext(Dispatchers.IO) {
            // Before the revoke: clearAllAppSettings enumerates permission callers to
            // find overrides whose mirror row is already gone, and revokeAllPermissions
            // empties that index.
            runAccountSwitchCleanup("clear app settings") { permissionStore?.clearAllAppSettings(signPolicyStore) }
            runAccountSwitchCleanup("revoke permissions") { permissionStore?.revokeAllPermissions() }
            runAccountSwitchCleanup("clear velocity") { permissionStore?.clearAllVelocity() }
            runAccountSwitchCleanup("clear caller trust") { callerVerificationStore?.clearAllTrust() }
            runAccountSwitchCleanup("clear auto-signing state") { autoSigningSafeguards?.clearAll() }
            runAccountSwitchCleanup("clear auto-sign rate limits") { signingRateLimiter?.clearAll() }
            runAccountSwitchCleanup("clear signing audit log") { permissionStore?.clearAuditLog() }
            runAccountSwitchCleanup("clear activity log") { eventLogStore?.clear() }
            // After the wipe, so it survives: the person has to know before turning the bunker on.
            if (bunkerResetFailed) {
                runAccountSwitchCleanup("record bunker reset failure") {
                    eventLogStore?.log(
                        EventLogCategory.BUNKER, EventLogLevel.ERROR, "bunker",
                        "The bunker could not be reset for this account and may still allow what was approved under the previous one; leave it off and switch accounts again to retry"
                    )
                }
            } else if (!bunkerResetComplete) {
                runAccountSwitchCleanup("record partial bunker reset") {
                    eventLogStore?.log(
                        EventLogCategory.BUNKER, EventLogLevel.WARN, "bunker",
                        "The bunker was not fully reset for this account; the reset finishes when the bunker is next turned on"
                    )
                }
            }
            // Genesis entry for the new account's fresh audit chain: the per-account wipe
            // above clears the prior trail, so record the activation itself here to keep
            // every account switch auditable (a switch is otherwise evidence-free).
            runAccountSwitchCleanup("record account-switch audit") {
                permissionStore?.logSelfEvent(AUDIT_OP_ACCOUNT_SWITCH)
            }
            // Last, and not through the permission store: this file has no
            // database behind it, so a store that never opened must not take it
            // down too, and running after the row steps means the marker that
            // protects a row is only dropped once the work on that row is done.
            // The startup migration writes these same keys and an account switch
            // does not cancel it, so going last also narrows the window in which
            // it can re-stamp what was just cleared.
            runAccountSwitchCleanup("retire the override migration") {
                clearAppOverrideMarkers(
                    getSharedPreferences(
                        SignPolicySelectionPrefs.MARKER_PREFS_NAME,
                        Context.MODE_PRIVATE
                    )
                )
            }
        }
        return !bunkerResetFailed
    }

    /**
     * Retires the override migration and drops the per-package markers it left.
     *
     * The markers are the residue: one plaintext key per package the previous
     * account had pinned, which is a record of which applications that identity
     * used and how many. The migration sweeps them itself once a run completes,
     * so what reaches here is the install whose run never completes, because it
     * still holds a row the sweep could not clear. The digest over the package
     * name is obfuscation and not confidentiality, so it is no answer to that.
     *
     * Clearing them alone would not be safe, which is why the run-wide marker is
     * set in the same commit. Each per-package marker is also what stops the
     * migration copying that row's tier into the core, so dropping one hands
     * that protection away: a row whose clear failed earlier in this wipe
     * survives carrying the previous account's tier, and the next launch would
     * copy it into the core, where the row and the core then agree on it and the
     * new account inherits it. Leaving the row one-sided instead resolves to the
     * strictest tier.
     *
     * Setting the marker costs nothing legitimate. After a switch no surviving
     * row's tier should ever be copied: it belongs to the previous account, and
     * on a clean wipe what survives are tombstones already rewritten to the
     * strictest tier. New choices are written to both sides directly and never
     * went through this migration.
     *
     * [markers] is a parameter so a test can drive this against a file of its
     * own: the real one is shared with the other migrations and with the
     * migration this app runs at startup, which writes and sweeps the same keys.
     */
    @androidx.annotation.VisibleForTesting
    internal fun clearAppOverrideMarkers(markers: SharedPreferences) {
        val edit = markers.edit()
            .putBoolean(SignPolicySelectionPrefs.APP_OVERRIDE_MIGRATION_MARKER, true)
        // Reads the committed state, so the marker staged above is not swept with
        // the per-package ones; it carries a different prefix either way.
        SignPolicySelectionPrefs.removeAppOverrideMarkers(markers, edit)
        if (!edit.commit() && BuildConfig.DEBUG) {
            // A wipe step that reports nothing is indistinguishable from a clean
            // one, which is what this file's own cleanup contract argues against.
            Log.e(TAG, "Per-app override markers could not be cleared")
        }
    }

    private suspend fun runAccountSwitchCleanup(label: String, action: suspend () -> Unit) {
        try {
            action()
        } catch (c: CancellationException) {
            throw c
        } catch (t: Throwable) {
            if (BuildConfig.DEBUG) Log.e(TAG, "Failed to $label on account switch", t)
        }
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

    /** Whether signing can use the node as it stands, rather than having to build one. */
    fun isNodeLive(): Boolean = liveState != null && liveNode.isLive()

    /**
     * For the operations after which the core has dropped its live node; see
     * [LiveNodeTracker]. No reconnect is attempted from here: building a node loads the
     * share, which needs an authenticated cipher this has no way to get, so the next
     * request that needs the node prompts for one and builds it.
     */
    fun onLiveNodeDropped() {
        liveNode.dropped()
        mainHandler.post {
            // Not over a node an initialize has built since this drop.
            if (!liveNode.isLive()) {
                liveState = null
                // The drop discards the node's pending requests without a state callback.
                io.privkey.keep.service.CosignNotifier.update(applicationContext, emptyList())
            }
        }
    }

    fun clearCertificatePin(hostname: String) {
        runCatching { keepMobile?.clearCertificatePin(hostname) }
            .onSuccess { if (it != null) onLiveNodeDropped() }
            .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to clearCertificatePin: ${it::class.simpleName}") }
    }

    fun clearAllCertificatePins() {
        runCatching { keepMobile?.clearCertificatePins() }
            .onSuccess { if (it != null) onLiveNodeDropped() }
            .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to clearCertificatePins: ${it::class.simpleName}") }
    }

    fun stageCertificatePin(hostname: String, spkiHash: String): Boolean =
        (keepMobile?.stageCertificatePinCompat(hostname, spkiHash) ?: false)
            .also { if (it) onLiveNodeDropped() }

    fun removeCertificatePin(hostname: String, spkiHash: String): CertPinRemoval? =
        keepMobile?.removeCertificatePinCompat(hostname, spkiHash)
            ?.also { onLiveNodeDropped() }

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

data class PinMismatchInfo(
    val hostname: String,
    val expected: String,
    val actual: String
) {
    override fun toString(): String = "PinMismatchInfo(hostname=$hostname)"
}
