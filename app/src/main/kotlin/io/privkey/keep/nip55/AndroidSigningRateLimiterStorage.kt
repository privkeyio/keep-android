package io.privkey.keep.nip55

import android.content.Context
import android.util.Log
import io.privkey.keep.BuildConfig
import io.privkey.keep.storage.KeystoreEncryptedPrefs
import io.privkey.keep.uniffi.SigningRateLimiterStorage
import io.privkey.keep.uniffi.StorageRead

private const val TAG = "RateLimiterStorage"

/**
 * Encrypted-prefs storage backend for the Rust [io.privkey.keep.uniffi.SigningRateLimiter].
 * Rust owns the velocity policy and clock handling; Android only persists the
 * opaque per-package counter/cooling-off entries.
 *
 * These entries gate auto-signing rather than merely describing it, so this class
 * has to be honest about failure in both directions:
 *
 * * A read that could not be completed reports [StorageRead.Unavailable], never
 *   [StorageRead.Absent]. Absent means "this package has no usage yet" and starts
 *   a fresh window, so reporting it for a failed read would reset the count on
 *   every request and put the hourly and daily ceilings out of reach entirely.
 * * A write reports the platform's own durable-write result. Reporting that the
 *   call did not throw would say nothing, because a commit can return false
 *   without raising, and Rust refuses to count a request it cannot record.
 *
 * Nothing here throws. A foreign method that throws across the FFI becomes an
 * unexpected-callback error and panics Rust on the signing path, so faults are
 * converted into the failure value instead.
 */
class AndroidSigningRateLimiterStorage(context: Context) : SigningRateLimiterStorage {

    private val prefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    override fun load(key: String): StorageRead =
        runCatching {
            // `contains` resolves the stored key name without decrypting its
            // value, which separates "never written" from "present but could not
            // be read". The backing store returns the default on a decrypt,
            // key-derivation, or decode failure, so without this check every
            // fault would masquerade as "no usage recorded".
            //
            // What it does NOT cover: the lookup hashes the key name with the
            // current derivation key, so an entry written under a previous key
            // epoch is invisible and still reports absent. Reaching that needs a
            // write failure that drops the store to its fallback key, followed by
            // recovery, and it resets one package's window rather than lifting
            // the ceiling. Closing it belongs to the key-registry handling, not
            // here. During the failure itself writes report false, so the core
            // refuses regardless.
            if (!prefs.contains(key)) {
                StorageRead.Absent
            } else {
                prefs.getString(key, null)?.let { StorageRead.Found(it) } ?: StorageRead.Unavailable
            }
        }.getOrElse {
            warn("load failed for $key", it)
            StorageRead.Unavailable
        }

    override fun save(key: String, value: String): Boolean =
        runCatching { prefs.edit().putString(key, value).commit() }
            .getOrElse {
                warn("save failed for $key", it)
                false
            }

    override fun remove(key: String): Boolean =
        runCatching { prefs.edit().remove(key).commit() }
            .getOrElse {
                warn("remove failed for $key", it)
                false
            }

    override fun clear(): Boolean =
        runCatching { prefs.edit().clear().commit() }
            .getOrElse {
                warn("clear failed", it)
                false
            }

    private fun warn(message: String, error: Throwable) {
        if (BuildConfig.DEBUG) Log.w(TAG, message, error)
    }

    companion object {
        private const val PREFS_NAME = "nip55_rate_limiter"
    }
}
