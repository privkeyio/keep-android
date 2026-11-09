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
 * ws/wss port omitted, any other port in decimal, a dotted IPv4 host in
 * canonical decimal (a leading-zero octet is octal), `.` / `..` path segments
 * removed, and a raw apostrophe percent-encoded in the query.
 *
 * TODO: remove this matcher, with [relayLinkFor], once the keep core emits one
 * health row per configured relay keyed by the configured string.
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

/** A u64 round trip past [Long.MAX_VALUE] is not a real latency, so it is unknown. */
internal fun rttMsOrNull(rtt: ULong?): Long? =
    rtt?.takeIf { it <= Long.MAX_VALUE.toULong() }?.toLong()

/** True when [url] names the same relay as one already in [relays]. */
internal fun isDuplicateRelay(url: String, relays: List<String>): Boolean {
    val key = normalizeRelayUrl(url)
    return relays.any { normalizeRelayUrl(it) == key }
}

/**
 * True for a host WHATWG parses as IPv4 in a form other than a four-part
 * dotted decimal, such as `1.2.3`, `0x7f.1` or `2130706433`. The core rewrites
 * those to dotted decimal, so a relay saved that way would never match its
 * health row. A host is caught when every label is decimal digits or `0x`
 * followed by hex digits, unless it is a valid dotted decimal quad (octal
 * octets included), which the matcher already canonicalizes.
 */
internal fun isNonCanonicalIpv4Host(url: String): Boolean {
    val host = url.substringAfter("://").substringBefore('/').substringBefore(':')
    if (!host.split('.').all { it.matches(NUMERIC_HOST_LABEL) }) return false
    return dottedQuadOrNull(host) == null
}

private val NUMERIC_HOST_LABEL = Regex("^([0-9]+|0[xX][0-9a-fA-F]*)$")

internal fun relayLinkFor(configuredUrl: String, links: List<RelayLinkHealth>): RelayLinkHealth? {
    val key = normalizeRelayUrl(configuredUrl)
    return links.find { normalizeRelayUrl(it.url) == key }
}

/**
 * Status a configured relay's row shows, or null for "Not connected": with no
 * pool up (node stopped, never started, or still building its pool) there is
 * nothing to report, and calling every relay offline would be wrong. Once the
 * pool is up, a configured relay with no core row is not in it, which is offline.
 */
internal fun relayRowStatus(link: RelayLinkHealth?, poolUp: Boolean): RelayLinkStatus? =
    if (poolUp) link?.status ?: RelayLinkStatus.OFFLINE else null

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
        val port = portText.toIntOrNull() ?: return authority
        return if (port == defaultPort) userInfo + host else "$userInfo$host:$port"
    }
    val colon = hostPort.lastIndexOf(':')
    if (colon < 0) return userInfo + canonicalIpv4Host(hostPort)
    host = hostPort.substring(0, colon)
    portText = hostPort.substring(colon + 1)
    val port = portText.toIntOrNull() ?: return authority
    val canonHost = canonicalIpv4Host(host)
    return if (port == defaultPort) userInfo + canonHost else "$userInfo$canonHost:$port"
}

/**
 * Four-octet IPv4 host, serialized the way url 2.5.8 does. An octet with a
 * leading zero is octal, so `010` is 8, and an 8 or 9 in that octet is not an
 * IPv4 host. Anything else is returned unchanged.
 */
private fun canonicalIpv4Host(host: String): String = dottedQuadOrNull(host) ?: host

private fun dottedQuadOrNull(host: String): String? {
    val parts = host.split('.')
    if (parts.size != 4) return null
    val numbers = ArrayList<Int>(4)
    for (part in parts) {
        val number = parseIpv4Octet(part) ?: return null
        if (number > 255) return null
        numbers.add(number)
    }
    return "${numbers[0]}.${numbers[1]}.${numbers[2]}.${numbers[3]}"
}

private fun parseIpv4Octet(input: String): Int? {
    if (input.isEmpty()) return null
    val octal = input.length >= 2 && input.startsWith('0')
    val digits = if (octal) input.substring(1) else input
    if (digits.isEmpty()) return 0
    val valid = if (octal) digits.all { it in '0'..'7' } else digits.all { it in '0'..'9' }
    if (!valid) return null
    return digits.toIntOrNull(if (octal) 8 else 10)
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
