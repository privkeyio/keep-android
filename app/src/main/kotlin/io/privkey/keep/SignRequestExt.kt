package io.privkey.keep

import io.privkey.keep.uniffi.SignRequest

/**
 * A human-readable summary of what a co-sign request will sign. A spend lists every
 * output, then the fee and the total, one per line, and is never shortened.
 */
fun SignRequest.describe(): String {
    val m = metadata
    spendLines()?.let { lines -> return (listOf(label()) + lines).filter { it.isNotEmpty() }.joinToString("\n") }
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
        append(label())
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

private fun SignRequest.label(): String =
    messageType.takeIf { it.isNotBlank() }?.let { if (typeVerified) it else "claimed: $it" } ?: ""

/**
 * Each output of a spend as "<amount> to <address>", then its fee and the total the
 * inputs supply, or null when the request carries no spend. An output with no address
 * on the account's network shows its whole script. No output is called change: the core
 * does not establish which ones return to the group.
 */
fun SignRequest.spendLines(): List<String>? {
    val spend = metadata?.spend ?: return null
    return spend.outputs.map { out ->
        val to = out.address?.takeIf { it.isNotBlank() } ?: "unrecognized script ${out.scriptHex}"
        "${formatSats(out.amountSats)} to $to"
    } + "Fee: ${formatSats(spend.feeSats)}" + "Total from inputs: ${formatSats(spend.consumedSats)}"
}

/**
 * For a notification, which cannot show a spend in full: how many outputs, the fee and
 * the total, and that the outputs are reviewed in the app. Null when there is no spend.
 */
fun SignRequest.spendOverview(): String? {
    val spend = metadata?.spend ?: return null
    val count = spend.outputs.size
    return listOf(
        label(),
        "${count} output${if (count == 1) "" else "s"} · fee ${formatSats(spend.feeSats)} · " +
            "total from inputs ${formatSats(spend.consumedSats)}",
        "Open Keep to review every output and approve.",
    ).filter { it.isNotEmpty() }.joinToString("\n")
}

internal fun formatSats(sats: ULong): String =
    sats.toString().reversed().chunked(3).joinToString(",").reversed() + " sats"

internal enum class CosignApproval { APPROVED, NOT_AUTHENTICATED, NO_SCREEN_LOCK }

/**
 * Whether the usual approval applies: from the notification, and in the app with the
 * usual authentication. Only for a Nostr event the core rebuilt from its body and matched
 * against the bytes being signed. Anything else, a spend, an unverified label or bare
 * bytes, could be a Bitcoin spend and is approved only in the app with a fresh prompt.
 * A peer chooses whether to send a body, so this asks for the positive case rather than
 * the absence of a spend. To be replaced by the core's own per-request approval level.
 */
internal fun SignRequest.usualApproval(): Boolean =
    typeVerified && metadata?.eventKind != null && metadata?.spend == null

/** Shown with a request the core could not check: what it signs is unknown. */
internal fun SignRequest.unverifiable(): Boolean = metadata == null

/**
 * Whether approving [request] in the app is authorized. A request outside the usual
 * approval always asks for a strong biometric or the lock-screen credential now, never
 * reusing an earlier authentication, and is refused on a device with no secure lock, or
 * one whose lock state is unknown. A verified Nostr event keeps the [usual] authentication.
 */
internal suspend fun authorizeCosign(
    request: SignRequest,
    deviceSecure: () -> Boolean?,
    strongOrCredential: suspend () -> Boolean,
    usual: suspend () -> Boolean,
): CosignApproval {
    if (request.usualApproval()) {
        return if (usual()) CosignApproval.APPROVED else CosignApproval.NOT_AUTHENTICATED
    }
    return when (deviceSecure()) {
        null -> CosignApproval.NOT_AUTHENTICATED
        false -> CosignApproval.NO_SCREEN_LOCK
        true -> if (strongOrCredential()) CosignApproval.APPROVED else CosignApproval.NOT_AUTHENTICATED
    }
}
