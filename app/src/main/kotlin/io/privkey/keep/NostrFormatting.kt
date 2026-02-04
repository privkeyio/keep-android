package io.privkey.keep

import io.privkey.keep.uniffi.pubkeyToNpub
import io.privkey.keep.uniffi.eventIdToNote

fun formatPubkeyDisplay(pubkey: String): String =
    runCatching { pubkeyToNpub(pubkey) }
        .map { npub -> "${npub.take(12)}...${npub.takeLast(8)}" }
        .getOrElse { if (pubkey.length > 24) "${pubkey.take(12)}...${pubkey.takeLast(8)}" else pubkey }

fun formatEventIdDisplay(eventId: String): String =
    runCatching { eventIdToNote(eventId) }
        .map { note -> "${note.take(12)}...${note.takeLast(8)}" }
        .getOrElse { if (eventId.length > 24) "${eventId.take(12)}...${eventId.takeLast(8)}" else eventId }
