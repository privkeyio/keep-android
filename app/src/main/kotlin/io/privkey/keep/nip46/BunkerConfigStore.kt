package io.privkey.keep.nip46

import io.privkey.keep.uniffi.BunkerConfigInfo
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.KeepMobileException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

object BunkerConfigStore {
    private val mutex = Mutex()
    private const val ATTEMPTS = 3

    suspend fun update(mobile: KeepMobile, transform: (BunkerConfigInfo) -> BunkerConfigInfo): BunkerConfigInfo =
        mutex.withLock { updateHeld(mobile, transform) }

    /**
     * [update] for a caller already inside [withLock]. A save that keeps the revision it read
     * is refused once the core changed the client list since, as a nostrconnect accept does
     * outside this lock, so the transform runs again on a fresh read. A save without one, as
     * the account-switch reset, replaces the list as given.
     */
    fun updateHeld(mobile: KeepMobile, transform: (BunkerConfigInfo) -> BunkerConfigInfo): BunkerConfigInfo {
        var attempt = 0
        while (true) {
            val updated = transform(mobile.getBunkerConfig())
            try {
                mobile.saveBunkerConfig(updated)
                return updated
            } catch (e: KeepMobileException.InvalidInput) {
                val stale = updated.revision != null &&
                    runCatching { mobile.getBunkerConfig().revision != updated.revision }
                        .onFailure(e::addSuppressed).getOrDefault(false)
                if (!stale || ++attempt >= ATTEMPTS) throw e
            }
        }
    }

    suspend fun <T> withLock(block: suspend () -> T): T = mutex.withLock { block() }
}
