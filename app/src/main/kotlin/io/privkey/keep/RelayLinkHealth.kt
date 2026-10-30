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
 * Core health URLs are `RelayUrl::as_str_without_trailing_slash` (WHATWG).
 * This only applies the parts of that form a relay saved from this app can
 * differ on: lowercase scheme and authority, no trailing slash, default
 * ws/wss port omitted, any other port in decimal, `.` / `..` path segments
 * removed, and a raw apostrophe percent-encoded in the query.
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
    val tail = if (pathStart < 0) "" else rest.substring(pathStart)
    val (beforeFragment, fragment) = splitOnce(tail, '#')
    val (path, query) = splitOnce(beforeFragment, '?')
    val encodedQuery = query?.replace("'", "%27")
    return buildString {
        append(scheme)
        append("://")
        append(stripDefaultRelayPort(scheme, authority.lowercase()))
        append(removeDotSegments(path))
        if (encodedQuery != null) {
            append('?')
            append(encodedQuery)
        }
        if (fragment != null) {
            append('#')
            append(fragment)
        }
    }.trimEnd('/')
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
    return if (port == defaultPort) userInfo + host else "$userInfo$host:$port"
}

/** WHATWG "remove dot segments", without decoding percent-escapes. */
private fun removeDotSegments(path: String): String {
    var input = path
    val output = StringBuilder()
    while (input.isNotEmpty()) {
        input = when {
            input.startsWith("../") -> input.substring(3)
            input.startsWith("./") -> input.substring(2)
            input.startsWith("/./") -> input.substring(2)
            input == "/." -> "/"
            input.startsWith("/../") -> {
                popLastSegment(output)
                input.substring(3)
            }
            input == "/.." -> {
                popLastSegment(output)
                "/"
            }
            input == "." || input == ".." -> ""
            else -> {
                val start = if (input.startsWith('/')) 1 else 0
                val slash = input.indexOf('/', start)
                if (slash < 0) {
                    output.append(input)
                    ""
                } else {
                    output.append(input.substring(0, slash))
                    input.substring(slash)
                }
            }
        }
    }
    return output.toString()
}

private fun popLastSegment(output: StringBuilder) {
    val slash = output.lastIndexOf('/')
    if (slash >= 0) output.setLength(slash)
}

private fun splitOnce(value: String, separator: Char): Pair<String, String?> {
    val index = value.indexOf(separator)
    if (index < 0) return value to null
    return value.substring(0, index) to value.substring(index + 1)
}
