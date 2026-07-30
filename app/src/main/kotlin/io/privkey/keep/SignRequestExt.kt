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
        // Qualified only when nothing checked it. A request carrying a
        // structured body has had its digest recomputed from that body and
        // matched against the bytes being signed, so its label is established;
        // one without is a bare claim. Marking both the same way trains people
        // to ignore the marking.
        //
        // The wording stays narrow on purpose. What was verified is the message
        // type, not the transaction: a verified Bitcoin sighash means these
        // bytes really are a taproot key-spend sighash for the supplied
        // transaction, not that it spends what the user expects or to whom.
        // A bare "verified" here would claim far more than was checked.
        //
        // The qualifier is ours and comes first, so a label chosen to look
        // authoritative still reads as asserted.
        messageType.takeIf { it.isNotBlank() }?.let {
            if (typeVerified) append(it) else append("claimed: ").append(it)
        }
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
