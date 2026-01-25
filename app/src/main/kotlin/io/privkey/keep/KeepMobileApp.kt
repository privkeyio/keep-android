package io.privkey.keep

import android.app.Application
import android.util.Log
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.KeepMobile

class KeepMobileApp : Application() {
    private var keepMobile: KeepMobile? = null
    private var storage: AndroidKeystoreStorage? = null

    override fun onCreate() {
        super.onCreate()
        initializeKeepMobile()
    }

    private fun initializeKeepMobile() {
        try {
            storage = AndroidKeystoreStorage(this)
            keepMobile = KeepMobile(storage!!)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize KeepMobile", e)
            keepMobile = null
            storage = null
        }
    }

    fun getKeepMobile(): KeepMobile? = keepMobile

    fun getStorage(): AndroidKeystoreStorage? = storage

    companion object {
        private const val TAG = "KeepMobileApp"
    }
}
