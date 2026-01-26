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
            val s = AndroidKeystoreStorage(this)
            val r = RelayConfigStore(this)
            val k = KeepMobile(s)
            storage = s
            relayConfigStore = r
            keepMobile = k
            nip55Handler = Nip55Handler(k)

            if (s.hasShare()) {
                val relays = r.getRelays()
                if (relays.isNotEmpty()) {
                    applicationScope.launch {
                        try {
                            k.initialize(relays)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to initialize with relays", e)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize KeepMobile", e)
        }
    }

    private fun initializePermissionStore() {
        try {
            val db = Nip55Database.getInstance(this)
            permissionStore = PermissionStore(db)
            applicationScope.launch {
                permissionStore?.cleanupExpired()
            }
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
        val k = keepMobile ?: return
        val r = relayConfigStore ?: return
        r.setRelays(relays)
        applicationScope.launch {
            try {
                k.initialize(relays)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to initialize with relays", e)
                onError(e.message ?: "Failed to connect")
            }
        }
    }

    companion object {
        private const val TAG = "KeepMobileApp"
    }
}
