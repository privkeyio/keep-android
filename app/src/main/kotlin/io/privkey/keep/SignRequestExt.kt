package io.privkey.keep

import io.privkey.keep.uniffi.SignRequest

/** A short, human-readable summary of what a co-sign request will sign. */
fun SignRequest.describe(): String {
    val m = metadata
    val sats = m?.amountSats
    if (sats != null) {
        val dest = m.destination?.takeIf { it.isNotBlank() }
        return if (dest != null) "$sats sats to $dest" else "$sats sats"
    }
    val content = m?.contentPreview?.takeIf { it.isNotBlank() }
        ?: messagePreview.takeIf { it.isNotBlank() }
    val kind = m?.eventKind
    return buildString {
        if (kind != null) append("kind $kind")
        if (content != null) {
            if (isNotEmpty()) append(" · ")
            append(content)
        }
        if (isEmpty()) append(messageType)
    }
}
