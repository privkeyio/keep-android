package io.privkey.keep

import android.app.Application
import android.util.Log
import io.privkey.keep.nip55.Nip55Database
import io.privkey.keep.nip55.PermissionStore
import io.privkey.keep.service.NetworkConnectivityManager
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.AutoStartStore
import io.privkey.keep.storage.KillSwitchStore
import io.privkey.keep.storage.RelayConfigStore
import io.privkey.keep.storage.SignPolicyStore
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.Nip55Handler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class KeepMobileApp : Application() {
    private var keepMobile: KeepMobile? = null
    private var storage: AndroidKeystoreStorage? = null
    private var relayConfigStore: RelayConfigStore? = null
    private var killSwitchStore: KillSwitchStore? = null
    private var signPolicyStore: SignPolicyStore? = null
    private var autoStartStore: AutoStartStore? = null
    private var nip55Handler: Nip55Handler? = null
    private var permissionStore: PermissionStore? = null
    private var networkManager: NetworkConnectivityManager? = null
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        initializeKeepMobile()
        initializePermissionStore()
        initializeNetworkMonitoring()
    }

    private fun initializeKeepMobile() {
        try {
            val newStorage = AndroidKeystoreStorage(this)
            val newRelayConfig = RelayConfigStore(this)
            val newKillSwitch = KillSwitchStore(this)
            val newSignPolicy = SignPolicyStore(this)
            val newAutoStart = AutoStartStore(this)
            val newKeepMobile = KeepMobile(newStorage)
            storage = newStorage
            relayConfigStore = newRelayConfig
            killSwitchStore = newKillSwitch
            signPolicyStore = newSignPolicy
            autoStartStore = newAutoStart
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
        if (autoStartStore?.isEnabled() != true) return
        networkManager = NetworkConnectivityManager(this) { reconnectRelays() }
        networkManager?.register()
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

    fun getKeepMobile(): KeepMobile? = keepMobile

    fun getStorage(): AndroidKeystoreStorage? = storage

    fun getRelayConfigStore(): RelayConfigStore? = relayConfigStore

    fun getKillSwitchStore(): KillSwitchStore? = killSwitchStore

    fun getSignPolicyStore(): SignPolicyStore? = signPolicyStore

    fun getAutoStartStore(): AutoStartStore? = autoStartStore

    fun getNip55Handler(): Nip55Handler? = nip55Handler

    fun getPermissionStore(): PermissionStore? = permissionStore

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
        val manager = networkManager ?: NetworkConnectivityManager(this) { reconnectRelays() }
            .also { networkManager = it }
        manager.register()
    }

    companion object {
        private const val TAG = "KeepMobileApp"
    }
}
