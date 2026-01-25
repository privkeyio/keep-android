package io.privkey.keep

import android.app.Application
import android.util.Log
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.Nip55Handler

class KeepMobileApp : Application() {
    private var keepMobile: KeepMobile? = null
    private var storage: AndroidKeystoreStorage? = null
    private var nip55Handler: Nip55Handler? = null

    override fun onCreate() {
        super.onCreate()
        initializeKeepMobile()
    }

    private fun initializeKeepMobile() {
        try {
            storage = AndroidKeystoreStorage(this)
            keepMobile = KeepMobile(storage!!)
            nip55Handler = Nip55Handler(keepMobile!!)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize KeepMobile", e)
            keepMobile = null
            storage = null
            nip55Handler = null
        }
    }

    fun getKeepMobile(): KeepMobile? = keepMobile

    fun getStorage(): AndroidKeystoreStorage? = storage

    fun getNip55Handler(): Nip55Handler? = nip55Handler

    companion object {
        private const val TAG = "KeepMobileApp"
    }
}
