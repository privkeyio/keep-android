package io.privkey.keep.nip55

import android.content.Context
import io.privkey.keep.storage.KeystoreEncryptedPrefs

/**
 * Per-package opt-in flag for background auto-signing. The velocity / cooling-off
 * policy lives in the Rust [io.privkey.keep.uniffi.SigningRateLimiter]
 * (see [AndroidSigningRateLimiterStorage]); this only stores whether a caller is
 * allowed to auto-sign at all.
 */
class AutoSigningSafeguards(context: Context) {

    companion object {
        private const val PREFS_NAME = "nip55_auto_signing"
        private const val KEY_PREFIX_OPTED_IN = "opted_in_"
    }

    private val prefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    fun isOptedIn(packageName: String): Boolean =
        prefs.getBoolean(KEY_PREFIX_OPTED_IN + packageName, false)

    fun setOptedIn(packageName: String, optedIn: Boolean) {
        prefs.edit().putBoolean(KEY_PREFIX_OPTED_IN + packageName, optedIn).apply()
    }

    fun clearAll() {
        prefs.edit().clear().commit()
    }
}
