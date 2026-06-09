package io.privkey.keep.nip46

import io.privkey.keep.uniffi.BunkerConfigInfo
import io.privkey.keep.uniffi.KeepMobile
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

object BunkerConfigStore {
    private val mutex = Mutex()

    suspend fun update(mobile: KeepMobile, transform: (BunkerConfigInfo) -> BunkerConfigInfo) {
        mutex.withLock {
            val current = mobile.getBunkerConfig()
            mobile.saveBunkerConfig(transform(current))
        }
    }
}
