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
        // Lead with the label. FROST signs the 32 bytes verbatim, so a nostr
        // event digest and a Bitcoin taproot sighash are byte-identical, and
        // this is the only thing telling them apart. It used to appear only when
        // everything else was blank, which for a real request never happened,
        // so the prompt showed a bare hash.
        //
        // Prefixed as a claim, and the prefix is ours and comes first, so a
        // label chosen to look authoritative still reads as asserted. The label
        // is not bound to the signed bytes: a peer can call a sighash anything
        // it likes. The core strips control characters and bidi overrides from
        // it before it reaches here, which makes it safe to render but says
        // nothing about whether it is true.
        messageType.takeIf { it.isNotBlank() }?.let { append("claimed: ").append(it) }
        if (kind != null) {
            if (isNotEmpty()) append(" · ")
            append("kind $kind")
        }
        if (content != null) {
            if (isNotEmpty()) append(" · ")
            append(content)
        }
    }
}
