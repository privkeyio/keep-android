package io.privkey.keep

import android.app.Application
import android.util.Log
import io.privkey.keep.nip55.Nip55Database
import io.privkey.keep.nip55.PermissionStore
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.RelayConfigStore
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
    private var nip55Handler: Nip55Handler? = null
    private var permissionStore: PermissionStore? = null
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        initializeKeepMobile()
        initializePermissionStore()
    }

    private fun initializeKeepMobile() {
        try {
            val newStorage = AndroidKeystoreStorage(this)
            val newRelayConfig = RelayConfigStore(this)
            val newKeepMobile = KeepMobile(newStorage)
            storage = newStorage
            relayConfigStore = newRelayConfig
            keepMobile = newKeepMobile
            nip55Handler = Nip55Handler(newKeepMobile)

            val relays = newRelayConfig.getRelays()
            if (newStorage.hasShare() && relays.isNotEmpty()) {
                applicationScope.launch {
                    runCatching { newKeepMobile.initialize(relays) }
                        .onFailure { Log.e(TAG, "Failed to initialize with relays", it) }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize KeepMobile", e)
        }
    }

    private fun initializePermissionStore() {
        try {
            val store = PermissionStore(Nip55Database.getInstance(this))
            permissionStore = store
            applicationScope.launch { store.cleanupExpired() }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize PermissionStore", e)
        }
    }

    fun getKeepMobile(): KeepMobile? = keepMobile

    fun getStorage(): AndroidKeystoreStorage? = storage

    fun getRelayConfigStore(): RelayConfigStore? = relayConfigStore

    fun getNip55Handler(): Nip55Handler? = nip55Handler

    fun getPermissionStore(): PermissionStore? = permissionStore

    fun initializeWithRelays(relays: List<String>, onError: (String) -> Unit) {
        val mobile = keepMobile ?: return
        val config = relayConfigStore ?: return
        config.setRelays(relays)
        applicationScope.launch {
            runCatching { mobile.initialize(relays) }
                .onFailure {
                    Log.e(TAG, "Failed to initialize with relays", it)
                    onError(it.message ?: "Failed to connect")
                }
        }
    }

    companion object {
        private const val TAG = "KeepMobileApp"
    }
}
