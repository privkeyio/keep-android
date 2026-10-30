package io.privkey.keep

/**
 * View of one FROST-pool relay, already classified by the core. Android only
 * matches these rows to the configured URL; it does not probe relays.
 */
internal enum class RelayLinkStatus {
    CONNECTING,
    CONNECTED,
    OFFLINE,
}

internal data class RelayLinkHealth(
    val url: String,
    val status: RelayLinkStatus,
    val lastConnectedMs: Long,
    val rttMs: Long?,
)

/**
 * Identity used to join a configured relay string to a core health row.
 * Mirrors `RelayUrl::as_str_without_trailing_slash`: lowercase scheme and
 * authority, drop a trailing slash, and drop the default ws/wss port.
 */
internal fun normalizeRelayUrl(raw: String): String {
    val trimmed = raw.trim()
    if (trimmed.isEmpty()) return trimmed
    val withScheme = if ("://" in trimmed) trimmed else "wss://$trimmed"
    val schemeSep = withScheme.indexOf("://")
    if (schemeSep < 0) return withScheme.trimEnd('/')
    val scheme = withScheme.substring(0, schemeSep).lowercase()
    val rest = withScheme.substring(schemeSep + 3)
    val pathStart = rest.indexOf('/')
    val authority = if (pathStart < 0) rest else rest.substring(0, pathStart)
    val path = if (pathStart < 0) "" else rest.substring(pathStart).trimEnd('/')
    return "$scheme://${stripDefaultRelayPort(scheme, authority.lowercase())}$path"
}

internal fun relayLinkFor(configuredUrl: String, links: List<RelayLinkHealth>): RelayLinkHealth? {
    val key = normalizeRelayUrl(configuredUrl)
    return links.find { normalizeRelayUrl(it.url) == key }
}

private fun stripDefaultRelayPort(scheme: String, authority: String): String {
    val defaultPort = when (scheme) {
        "wss" -> 443
        "ws" -> 80
        else -> return authority
    }
    val at = authority.lastIndexOf('@')
    val userInfo = if (at >= 0) authority.substring(0, at + 1) else ""
    val hostPort = if (at >= 0) authority.substring(at + 1) else authority
    val host: String
    val portText: String
    if (hostPort.startsWith("[")) {
        val bracket = hostPort.indexOf(']')
        if (bracket < 0 || hostPort.getOrNull(bracket + 1) != ':') return authority
        host = hostPort.substring(0, bracket + 1)
        portText = hostPort.substring(bracket + 2)
    } else {
        val colon = hostPort.lastIndexOf(':')
        if (colon < 0) return authority
        host = hostPort.substring(0, colon)
        portText = hostPort.substring(colon + 1)
    }
    val port = portText.toIntOrNull() ?: return authority
    return if (port == defaultPort) userInfo + host else authority
}
