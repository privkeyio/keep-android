package io.privkey.keep.nip55

private val SENSITIVE_KINDS = setOf(0, 3, 10002)

fun isSensitiveKind(kind: Int): Boolean = kind in SENSITIVE_KINDS

fun eventKindName(kind: Int): String = EventKind.displayName(kind)

fun sensitiveKindWarning(kind: Int): String? = when (kind) {
    0 -> "Modifying profile metadata can affect your identity across all Nostr clients"
    3 -> "Modifying contacts can affect who you follow across all Nostr clients"
    10002 -> "Modifying relay list can affect your connectivity across all Nostr clients"
    else -> null
}
