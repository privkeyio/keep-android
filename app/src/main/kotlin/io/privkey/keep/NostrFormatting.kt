package io.privkey.keep

import io.privkey.keep.uniffi.eventIdToNote
import io.privkey.keep.uniffi.pubkeyToNpub

private fun truncate(value: String): String =
    if (value.length > 20) "${value.take(12)}...${value.takeLast(8)}" else value

fun formatPubkeyDisplay(pubkey: String): String =
    runCatching { pubkeyToNpub(pubkey) }.getOrNull()?.let { truncate(it) } ?: truncate(pubkey)

fun formatEventIdDisplay(eventId: String): String =
    runCatching { eventIdToNote(eventId) }.getOrNull()?.let { truncate(it) } ?: truncate(eventId)
