package io.privkey.keep

import android.app.Application
import android.util.Log
import io.privkey.keep.nip55.Nip55Database
import io.privkey.keep.nip55.PermissionStore
import io.privkey.keep.service.KeepAliveService
import io.privkey.keep.service.NetworkConnectivityManager
import io.privkey.keep.service.SigningNotificationManager
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.AutoStartStore
import io.privkey.keep.storage.ForegroundServiceStore
import io.privkey.keep.storage.KillSwitchStore
import io.privkey.keep.storage.PinStore
import io.privkey.keep.storage.RelayConfigStore
import io.privkey.keep.storage.SignPolicyStore
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.Nip55Handler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

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
    private var nip55Handler: Nip55Handler? = null
    private var permissionStore: PermissionStore? = null
    private var networkManager: NetworkConnectivityManager? = null
    private var signingNotificationManager: SigningNotificationManager? = null
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        initializeKeepMobile()
        initializePermissionStore()
        initializeNetworkMonitoring()
        initializeForegroundService()
        initializeNotifications()
    }

    private fun initializeKeepMobile() {
        try {
            val newStorage = AndroidKeystoreStorage(this)
            val newRelayConfig = RelayConfigStore(this)
            val newKillSwitch = KillSwitchStore(this)
            val newSignPolicy = SignPolicyStore(this)
            val newAutoStart = AutoStartStore(this)
            val newForegroundService = ForegroundServiceStore(this)
            val newPinStore = PinStore(this)
            val newKeepMobile = KeepMobile(newStorage)
            storage = newStorage
            relayConfigStore = newRelayConfig
            killSwitchStore = newKillSwitch
            signPolicyStore = newSignPolicy
            autoStartStore = newAutoStart
            foregroundServiceStore = newForegroundService
            pinStore = newPinStore
            keepMobile = newKeepMobile
            nip55Handler = Nip55Handler(newKeepMobile)

            val relays = newRelayConfig.getRelays()
            if (newStorage.hasShare() && relays.isNotEmpty()) {
                applicationScope.launch {
                    runCatching { newKeepMobile.initialize(relays) }
                        .onFailure { Log.e(TAG, "Failed to initialize with relays: ${it::class.simpleName}") }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize KeepMobile: ${e::class.simpleName}", e)
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
            applicationScope.launch { store.cleanupExpired() }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize PermissionStore: ${e::class.simpleName}")
        }
    }

    private fun initializeNotifications() {
        try {
            val manager = SigningNotificationManager(this)
            signingNotificationManager = manager
            applicationScope.launch { manager.cleanupStaleEntries() }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize SigningNotificationManager: ${e::class.simpleName}", e)
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

    fun getNip55Handler(): Nip55Handler? = nip55Handler

    fun getPermissionStore(): PermissionStore? = permissionStore

    fun getSigningNotificationManager(): SigningNotificationManager? = signingNotificationManager

    fun initializeWithRelays(relays: List<String>, onError: (String) -> Unit) {
        val mobile = keepMobile ?: run {
            Log.e(TAG, "Cannot initialize: KeepMobile not available")
            onError("KeepMobile not initialized")
            return
        }
        val config = relayConfigStore ?: run {
            Log.e(TAG, "Cannot initialize: RelayConfigStore not available")
            onError("Relay configuration not available")
            return
        }
        config.setRelays(relays)
        applicationScope.launch {
            runCatching { mobile.initialize(relays) }
                .onFailure {
                    Log.e(TAG, "Failed to initialize with relays: ${it::class.simpleName}")
                    onError("Failed to connect to relays")
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
            runCatching { mobile.initialize(relays) }
                .onFailure { Log.e(TAG, "Failed to reconnect relays: ${it::class.simpleName}") }
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
}
