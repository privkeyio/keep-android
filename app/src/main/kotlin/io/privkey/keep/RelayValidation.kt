package io.privkey.keep

import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI

internal val RELAY_URL_REGEX = Regex("^wss://[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:\\d{1,5})?(/[a-zA-Z0-9._~:/?#\\[\\]@!\$&'()*+,;=-]*)?$")
internal val HEX_PUBKEY_REGEX = Regex("^[a-fA-F0-9]{64}$")
internal const val MAX_BUNKER_RELAYS = 5
internal const val MAX_AUTHORIZED_CLIENTS = 50

internal fun isValidRelayPort(url: String): Boolean {
    val portStr = Regex(":(\\d+)").find(url.substringAfter("://"))?.groupValues?.get(1) ?: return true
    val port = portStr.toIntOrNull() ?: return false
    return port in 1..65535
}

private fun parseHost(url: String): String? = runCatching {
    URI(url).host?.removeSurrounding("[", "]")
}.getOrNull()

private fun resolveAddresses(host: String): List<InetAddress>? {
    if (host.equals("localhost", ignoreCase = true)) return null
    return runCatching { InetAddress.getAllByName(host).toList() }.getOrNull()
}

internal fun isInternalHost(url: String): Boolean {
    val host = parseHost(url) ?: return true
    val addresses = resolveAddresses(host) ?: return true
    return addresses.any { isInternalAddress(it) }
}

// NOTE: DNS is resolved here but the actual WebSocket connection happens later.
// A DNS rebinding attack could return a safe address here and an internal address
// at connection time. Full mitigation requires pinning resolved addresses at the
// socket layer, which is not currently supported by the WebSocket library.
internal fun filterRelaysPreConnection(relays: List<String>): List<String> {
    return relays.filter { url ->
        val host = parseHost(url) ?: return@filter false
        val addresses = resolveAddresses(host) ?: return@filter false
        addresses.none { isInternalAddress(it) }
    }
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
        if (b0 == 100 && (b1 and 0xC0) == 64) return true
    }
    if (addr is Inet6Address || bytes.size == 16) {
        if ((bytes[0].toInt() and 0xFE) == 0xFC) {
            return true
        }
    }
    return isIPv4MappedPrivate(addr)
}

private fun isIPv4MappedPrivate(addr: InetAddress): Boolean {
    val bytes = addr.address
    if (bytes.size != 16) return false
    for (i in 0..9) {
        if (bytes[i] != 0.toByte()) return false
    }
    if (bytes[10] != 0xFF.toByte() || bytes[11] != 0xFF.toByte()) return false
    val ipv4 = byteArrayOf(bytes[12], bytes[13], bytes[14], bytes[15])
    val mappedAddr = runCatching { InetAddress.getByAddress(ipv4) }.getOrNull() ?: return false
    return isInternalAddress(mappedAddr)
}
