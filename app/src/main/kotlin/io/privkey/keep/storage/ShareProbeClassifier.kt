package io.privkey.keep.storage

import io.privkey.keep.uniffi.ShareProbe
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * A key opened for decryption, the platform's word that it never will be, or its
 * refusal to start until the owner authenticates.
 */
internal sealed interface OpenedKey {
    data class Ready(val cipher: Cipher) : OpenedKey
    data object Invalidated : OpenedKey
    data object NeedsAuth : OpenedKey
}

/**
 * The Keystore as the probe sees it. Every method may throw, and any throw makes the
 * probe answer [ShareProbe.Unknown]. None of them may create a key or wait on the user.
 */
internal interface ShareProbeKeystore {
    /** Whether a key that must exist answers, so a missing alias can be trusted. */
    fun canaryPresent(): Boolean

    /** The key under [alias], or null only when the Keystore reports it absent. */
    fun secretKey(alias: String): SecretKey?

    fun requiresUserAuth(key: SecretKey): Boolean

    fun open(key: SecretKey, iv: ByteArray): OpenedKey

    /** The cipher the owner authenticated for this request, taken once, if any. */
    fun authenticatedCipher(): Cipher?
}

/**
 * Whether a share's secret still decrypts, is provably lost, or cannot be told.
 *
 * [ShareProbe.Lost] needs positive evidence: every alias the share could use reported
 * absent while the canary answered before and after, a record [recordEmpty] confirms
 * holds nothing, or every existing key either permanently invalidated or failing GCM
 * authentication on a cleanly read IV and ciphertext. A key that needs the owner's
 * authentication is tried only with the request's authenticated cipher, and only when
 * it is the one such key, since an unauthorized decrypt says nothing about the
 * ciphertext. Everything else is [ShareProbe.Unknown].
 */
internal fun classifyShare(
    aliases: List<String>,
    iv: ByteArray?,
    ciphertext: ByteArray?,
    keystore: ShareProbeKeystore,
    recordEmpty: Boolean = false,
): ShareProbe = try {
    classify(aliases.distinct(), iv, ciphertext, keystore, recordEmpty)
} catch (e: Exception) {
    ShareProbe.Unknown
}

private fun classify(
    aliases: List<String>,
    iv: ByteArray?,
    ciphertext: ByteArray?,
    keystore: ShareProbeKeystore,
    recordEmpty: Boolean,
): ShareProbe {
    if (!keystore.canaryPresent()) return ShareProbe.Unknown
    val keys = aliases.mapNotNull(keystore::secretKey)
    if (!keystore.canaryPresent()) return ShareProbe.Unknown
    if (keys.isEmpty()) return ShareProbe.Lost
    // A key with no ciphertext left to open, as after a delete that cleared the record
    // but failed before deregistering it. Half a record could be an interrupted write.
    if (iv == null && ciphertext == null && recordEmpty) return ShareProbe.Lost
    if (iv == null || ciphertext == null) return ShareProbe.Unknown
    if (ciphertext.size < GCM_TAG_BYTES) return ShareProbe.Lost

    var lost = 0
    val needAuth = mutableListOf<SecretKey>()
    for (key in keys) {
        val opened = keystore.open(key, iv)
        if (opened == OpenedKey.Invalidated) {
            lost++
            continue
        }
        // Without the owner's authorization a decrypt fails as an illegal block size,
        // never a bad tag, so it would only answer Unknown. Such a key waits for the
        // authenticated cipher instead.
        if (opened == OpenedKey.NeedsAuth || keystore.requiresUserAuth(key)) {
            needAuth += key
            continue
        }
        val cipher = (opened as OpenedKey.Ready).cipher
        when (val plain = decrypt(cipher, ciphertext)) {
            null -> lost++
            else -> return ShareProbe.Loads(plain)
        }
    }
    when (needAuth.size) {
        0 -> Unit
        1 -> {
            val cipher = keystore.authenticatedCipher() ?: return ShareProbe.Unknown
            // The cipher was opened before the owner's prompt. One opened on another IV
            // would fail the tag on data that still decrypts.
            if (!cipher.iv.contentEquals(iv)) return ShareProbe.Unknown
            when (val plain = decrypt(cipher, ciphertext)) {
                null -> lost++
                else -> return ShareProbe.Loads(plain)
            }
        }
        else -> return ShareProbe.Unknown
    }
    return if (lost == keys.size) ShareProbe.Lost else ShareProbe.Unknown
}

/** The plaintext, or null when GCM authentication fails. Any other failure throws. */
private fun decrypt(cipher: Cipher, ciphertext: ByteArray): ByteArray? = try {
    cipher.doFinal(ciphertext)
} catch (e: AEADBadTagException) {
    null
}

private const val GCM_TAG_BYTES = 16
