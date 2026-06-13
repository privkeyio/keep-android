package io.privkey.keep.nip55

import android.util.Log
import io.privkey.keep.BuildConfig
import io.privkey.keep.uniffi.Nip55RequestType
import java.security.MessageDigest

private const val TAG = "PubkeyVerification"

/**
 * Integrity check for a get_public_key handler result. Returns an error code if
 * the [resultString] is empty, the stored [groupPubkey] is missing/empty, or the
 * two do not match (constant-time, on the hex-encoded bytes the handler emits);
 * else null. Non-get_public_key request types trivially pass.
 *
 * Takes its inputs as parameters (no Activity state) so it is fully unit-testable.
 */
internal fun checkPubkey(
    requestType: Nip55RequestType?,
    resultString: String,
    groupPubkey: ByteArray?
): String? {
    if (requestType != Nip55RequestType.GET_PUBLIC_KEY) return null
    if (resultString.isEmpty()) {
        if (BuildConfig.DEBUG) Log.e(TAG, "Handler returned empty pubkey result")
        return "pubkey_verification_failed"
    }
    if (groupPubkey == null || groupPubkey.isEmpty()) {
        if (BuildConfig.DEBUG) Log.e(TAG, "Stored pubkey unavailable for verification")
        return "pubkey_verification_failed"
    }
    val storedPubkey = groupPubkey.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    if (!MessageDigest.isEqual(resultString.toByteArray(Charsets.UTF_8), storedPubkey.toByteArray(Charsets.UTF_8))) {
        if (BuildConfig.DEBUG) Log.e(TAG, "Pubkey verification failed: mismatch detected")
        return "pubkey_verification_failed"
    }
    return null
}
