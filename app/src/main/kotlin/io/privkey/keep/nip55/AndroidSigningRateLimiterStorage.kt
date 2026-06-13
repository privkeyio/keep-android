package io.privkey.keep.nip55

import android.content.Context
import io.privkey.keep.storage.KeystoreEncryptedPrefs
import io.privkey.keep.uniffi.SigningRateLimiterStorage

/**
 * Encrypted-prefs storage backend for the Rust [io.privkey.keep.uniffi.SigningRateLimiter].
 * Rust owns the velocity policy and clock handling; Android only persists the
 * opaque per-package counter/cooling-off entries.
 */
class AndroidSigningRateLimiterStorage(context: Context) : SigningRateLimiterStorage {

    private val prefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    override fun load(key: String): String? = prefs.getString(key, null)

    override fun save(key: String, value: String) {
        prefs.edit().putString(key, value).commit()
    }

    override fun remove(key: String) {
        prefs.edit().remove(key).commit()
    }

    override fun clear() {
        prefs.edit().clear().commit()
    }

    companion object {
        private const val PREFS_NAME = "nip55_rate_limiter"
    }
}
