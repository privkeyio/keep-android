package io.privkey.keep.nip46

import io.privkey.keep.uniffi.BunkerConfigInfo
import io.privkey.keep.uniffi.KeepMobile
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

object BunkerConfigStore {
    private val mutex = Mutex()

    suspend fun update(mobile: KeepMobile, transform: (BunkerConfigInfo) -> BunkerConfigInfo): BunkerConfigInfo {
        return mutex.withLock {
            val current = mobile.getBunkerConfig()
            val updated = transform(current)
            mobile.saveBunkerConfig(updated)
            updated
        }
    }

    suspend fun <T> withLock(block: suspend () -> T): T = mutex.withLock { block() }
}
