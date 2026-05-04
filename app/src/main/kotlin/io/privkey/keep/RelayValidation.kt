package io.privkey.keep

import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI

internal val RELAY_URL_REGEX = Regex("^wss://[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:\\d{1,5})?(/[a-zA-Z0-9._~:/?#\\[\\]@!\$&'()*+,;=-]*)?$")
internal val HEX_PUBKEY_REGEX = Regex("^[a-fA-F0-9]{64}$")
internal const val MAX_BUNKER_RELAYS = 5
internal const val MAX_AUTHORIZED_CLIENTS = 50

internal enum class RelayHostCheck { REACHABLE, UNRESOLVABLE, INTERNAL }

internal fun isValidRelayPort(url: String): Boolean {
    val portStr = Regex(":(\\d+)").find(url.substringAfter("://"))?.groupValues?.get(1) ?: return true
    val port = portStr.toIntOrNull() ?: return false
    return port in 1..65535
}

private fun parseHost(url: String): String? = runCatching {
    URI(url).host?.removeSurrounding("[", "]")
}.getOrNull()

private fun resolveAddresses(host: String): List<InetAddress>? =
    runCatching { InetAddress.getAllByName(host).toList() }.getOrNull()

internal fun checkRelayHost(url: String): RelayHostCheck {
    val host = parseHost(url) ?: return RelayHostCheck.INTERNAL
    if (host.equals("localhost", ignoreCase = true)) return RelayHostCheck.INTERNAL
    val addresses = resolveAddresses(host) ?: return RelayHostCheck.UNRESOLVABLE
    return when {
        addresses.isEmpty() -> RelayHostCheck.UNRESOLVABLE
        addresses.any { isInternalAddress(it) } -> RelayHostCheck.INTERNAL
        else -> RelayHostCheck.REACHABLE
    }
}

internal fun isInternalHost(url: String): Boolean = checkRelayHost(url) != RelayHostCheck.REACHABLE

// NOTE: DNS is resolved here but the actual WebSocket connection happens later in the
// Rust SDK, which manages its own resolver. A DNS rebinding attack could return a public
// address here and an internal address at connection time. Full mitigation would require
// pinning resolved addresses at the socket layer, which the underlying client does not
// currently expose. We minimize the TOCTOU window by resolving immediately before
// handing relays to the connection layer and rejecting any host that resolves to an
// internal/reserved address.
internal fun filterRelaysPreConnection(relays: List<String>): List<String> {
    return relays.filter { url -> checkRelayHost(url) == RelayHostCheck.REACHABLE }
}

internal fun isInternalAddress(addr: InetAddress): Boolean {
    if (addr.isLoopbackAddress ||
        addr.isLinkLocalAddress ||
        addr.isSiteLocalAddress ||
        addr.isAnyLocalAddress ||
        addr.isMulticastAddress) {
        return true
    }
    val bytes = addr.address
    if (bytes.size == 4) {
        val b0 = bytes[0].toInt() and 0xFF
        val b1 = bytes[1].toInt() and 0xFF
        val b2 = bytes[2].toInt() and 0xFF
        // 100.64.0.0/10 (CGNAT)
        if (b0 == 100 && (b1 and 0xC0) == 64) return true
        // 192.0.0.0/24 (IETF protocol assignments)
        if (b0 == 192 && b1 == 0 && b2 == 0) return true
        // 192.0.2.0/24 (TEST-NET-1)
        if (b0 == 192 && b1 == 0 && b2 == 2) return true
        // 198.51.100.0/24 (TEST-NET-2)
        if (b0 == 198 && b1 == 51 && b2 == 100) return true
        // 203.0.113.0/24 (TEST-NET-3)
        if (b0 == 203 && b1 == 0 && b2 == 113) return true
        // 198.18.0.0/15 (benchmark)
        if (b0 == 198 && (b1 and 0xFE) == 18) return true
        // 240.0.0.0/4 (reserved, including 255.255.255.255 broadcast)
        if ((b0 and 0xF0) == 0xF0) return true
    }
    if (addr is Inet6Address || bytes.size == 16) {
        // fc00::/7 (unique local)
        if ((bytes[0].toInt() and 0xFE) == 0xFC) return true
        val b0 = bytes[0].toInt() and 0xFF
        val b1 = bytes[1].toInt() and 0xFF
        val b2 = bytes[2].toInt() and 0xFF
        val b3 = bytes[3].toInt() and 0xFF
        // 2002::/16 (6to4): embedded IPv4 in bytes 2..5
        if (b0 == 0x20 && b1 == 0x02 && embeddedIPv4IsInternal(bytes, 2)) return true
        // 64:ff9b::/96 (NAT64 well-known)
        if (b0 == 0x00 && b1 == 0x64 && b2 == 0xFF && b3 == 0x9B &&
            (4..11).all { bytes[it] == 0.toByte() } &&
            embeddedIPv4IsInternal(bytes, 12)) return true
        // ::ffff:0:0/96 (IPv4-mapped) and ::/96 (IPv4-compatible, deprecated but treat as suspect)
        if ((0..9).all { bytes[it] == 0.toByte() }) {
            val isMapped = bytes[10] == 0xFF.toByte() && bytes[11] == 0xFF.toByte()
            val isCompat = bytes[10] == 0.toByte() && bytes[11] == 0.toByte()
            if (isMapped || isCompat) {
                val ipv4 = byteArrayOf(bytes[12], bytes[13], bytes[14], bytes[15])
                val mappedAddr = runCatching { InetAddress.getByAddress(ipv4) }.getOrNull()
                if (mappedAddr != null) {
                    // Block ::/96 except the unspecified address itself and ::1 loopback
                    // (already handled by isLoopback / isAnyLocal above). Treat the rest as reserved.
                    if (isCompat) return true
                    if (isInternalAddress(mappedAddr)) return true
                }
            }
        }
    }
    return false
}

private fun embeddedIPv4IsInternal(bytes: ByteArray, offset: Int): Boolean {
    val ipv4 = byteArrayOf(bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3])
    val embeddedAddr = runCatching { InetAddress.getByAddress(ipv4) }.getOrNull() ?: return false
    return isInternalAddress(embeddedAddr)
}
