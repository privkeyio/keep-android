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

internal fun isInternalHost(url: String): Boolean {
    val host = runCatching {
        val uri = URI(url)
        uri.host?.removeSurrounding("[", "]")
    }.getOrNull() ?: return true

    if (host.equals("localhost", ignoreCase = true)) return true

    val addresses = runCatching { InetAddress.getAllByName(host) }.getOrNull() ?: return true
    return addresses.any { isInternalAddress(it) }
}

private fun isInternalAddress(addr: InetAddress): Boolean {
    if (addr.isLoopbackAddress ||
        addr.isLinkLocalAddress ||
        addr.isSiteLocalAddress ||
        addr.isAnyLocalAddress) {
        return true
    }
    if (addr is Inet6Address || addr.address.size == 16) {
        val bytes = addr.address
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
    return mappedAddr.isLoopbackAddress ||
        mappedAddr.isLinkLocalAddress ||
        mappedAddr.isSiteLocalAddress
}
