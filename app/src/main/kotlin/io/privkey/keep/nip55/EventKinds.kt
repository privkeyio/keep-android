package io.privkey.keep.nip55

private val SENSITIVE_KINDS = setOf(
    0,      // Metadata (profile)
    3,      // Contacts (follow list)
    4,      // Encrypted Direct Message (NIP-04)
    1059,   // Gift Wrap (NIP-59)
    1984,   // Report
    10000,  // Mute List
    10002,  // Relay List Metadata
    10003,  // Bookmark List
    10004,  // Search Relay List
    10006,  // Blocked Relays List
    10050   // DM Relay List
)

fun isSensitiveKind(kind: Int): Boolean =
    kind in SENSITIVE_KINDS || kind in 30000..39999

fun sensitiveKindWarning(kind: Int): String? = when (kind) {
    0 -> "Modifying profile metadata can affect your identity across all Nostr clients"
    3 -> "Modifying contacts can affect who you follow across all Nostr clients"
    4 -> "Encrypted direct messages contain private communications"
    1059 -> "Gift wrapped events may contain private communications"
    1984 -> "Reports can affect reputation and content moderation"
    10000 -> "Modifying mute list can affect your experience across all Nostr clients"
    10002 -> "Modifying relay list can affect your connectivity across all Nostr clients"
    10003 -> "Modifying bookmarks can affect your saved content across all Nostr clients"
    10004 -> "Modifying search relay list can affect your search experience"
    10006 -> "Modifying blocked relays can affect your connectivity"
    10050 -> "Modifying DM relay list can affect your private messaging across all Nostr clients"
    in 30000..39999 -> "Replaceable events can be overwritten and may contain sensitive data"
    else -> null
}
