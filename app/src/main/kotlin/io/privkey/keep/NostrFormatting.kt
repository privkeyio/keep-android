package io.privkey.keep

import java.util.Arrays

internal const val BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
private val HEX_REGEX = Regex("^[0-9a-fA-F]+$")
private const val NSEC_PAYLOAD_LENGTH = 58

internal fun isHex64(value: String): Boolean = value.length == 64 && HEX_REGEX.matches(value)

internal fun isValidNsecFormat(data: String): Boolean {
    val lower = data.lowercase()
    if (!lower.startsWith("nsec1")) return false
    val payload = lower.removePrefix("nsec1")
    if (payload.length != NSEC_PAYLOAD_LENGTH || !payload.all { it in BECH32_CHARSET }) return false
    val key = nsecToBytes(lower) ?: return false
    Arrays.fill(key, 0.toByte())
    return true
}

internal fun nsecToBytes(nsec: String): ByteArray? {
    val decoded = bech32Decode(nsec) ?: return null
    if (decoded.first != "nsec") return null
    val values = convertBits(decoded.second, 5, 8, false) ?: return null
    if (values.size != 32) return null
    return ByteArray(values.size) { (values[it] and 0xFF).toByte() }
}

private fun bech32Decode(bech32: String): Pair<String, List<Int>>? {
    if (bech32 != bech32.lowercase() && bech32 != bech32.uppercase()) return null
    val lower = bech32.lowercase()
    val pos = lower.lastIndexOf('1')
    if (pos < 1 || pos + 7 > lower.length) return null
    val hrp = lower.substring(0, pos)
    val dataChars = lower.substring(pos + 1)
    val data = dataChars.map { BECH32_CHARSET.indexOf(it) }.takeIf { vals -> vals.all { it >= 0 } } ?: return null
    val values = bech32HrpExpand(hrp) + data
    if (bech32Polymod(values) != 1) return null
    return hrp to data.dropLast(6)
}

private fun truncate(value: String): String =
    if (value.length > 20) "${value.take(12)}...${value.takeLast(8)}" else value

fun formatPubkeyDisplay(pubkey: String): String =
    hexToBech32(pubkey, "npub")?.let { truncate(it) } ?: truncate(pubkey)

fun formatEventIdDisplay(eventId: String, relayUrl: String? = null): String =
    hexToNevent(eventId, relayUrl)?.let { truncate(it) } ?: truncate(eventId)

fun hexToNpub(hex: String): String = hexToBech32(hex, "npub") ?: ""

private fun hexToNevent(eventId: String, relayUrl: String?): String? {
    if (!isHex64(eventId)) return null
    return try {
        val idBytes = eventId.chunked(2).map { it.toInt(16).toByte() }
        val tlv = mutableListOf<Byte>()
        tlv.add(0) // type 0: special (event id)
        tlv.add(32) // length: 32 bytes
        tlv.addAll(idBytes)
        if (!relayUrl.isNullOrEmpty()) {
            val relayBytes = relayUrl.toByteArray(Charsets.US_ASCII)
            tlv.add(1) // type 1: relay
            tlv.add(relayBytes.size.toByte())
            tlv.addAll(relayBytes.toList())
        }
        bech32Encode("nevent", convertBits(tlv.map { it.toInt() and 0xFF }, 8, 5, true) ?: return null)
    } catch (e: Exception) {
        if (io.privkey.keep.BuildConfig.DEBUG) android.util.Log.w("NostrFormatting", "hexToNevent failed", e)
        null
    }
}

private fun hexToBech32(hex: String, hrp: String): String? {
    if (!isHex64(hex)) return null
    return try {
        val bytes = hex.chunked(2).map { it.toInt(16) }
        bech32Encode(hrp, convertBits(bytes, 8, 5, true) ?: return null)
    } catch (e: Exception) {
        if (io.privkey.keep.BuildConfig.DEBUG) android.util.Log.w("NostrFormatting", "hexToBech32 failed", e)
        null
    }
}

private fun convertBits(data: List<Int>, fromBits: Int, toBits: Int, pad: Boolean): List<Int>? {
    var acc = 0
    var bits = 0
    val result = mutableListOf<Int>()
    val maxV = (1 shl toBits) - 1
    for (v in data) {
        acc = (acc shl fromBits) or v
        bits += fromBits
        while (bits >= toBits) {
            bits -= toBits
            result.add((acc shr bits) and maxV)
        }
    }
    if (pad && bits > 0) {
        result.add((acc shl (toBits - bits)) and maxV)
    } else if (!pad && bits > 0) {
        if ((acc shl (toBits - bits)) and maxV != 0) return null
    }
    return result
}

private fun bech32Encode(hrp: String, data: List<Int>): String {
    val checksum = bech32CreateChecksum(hrp, data)
    val combined = data + checksum
    val dataChars = combined.map { BECH32_CHARSET[it] }.joinToString("")
    return "${hrp}1${dataChars}"
}

private fun bech32CreateChecksum(hrp: String, data: List<Int>): List<Int> {
    val values = bech32HrpExpand(hrp) + data + listOf(0, 0, 0, 0, 0, 0)
    val polymod = bech32Polymod(values) xor 1
    return (0..5).map { (polymod shr (5 * (5 - it))) and 31 }
}

private fun bech32HrpExpand(hrp: String): List<Int> =
    hrp.map { it.code shr 5 } + 0 + hrp.map { it.code and 31 }

private fun bech32Polymod(values: List<Int>): Int {
    val generator = listOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    var chk = 1
    for (v in values) {
        val top = chk shr 25
        chk = ((chk and 0x1ffffff) shl 5) xor v
        for (i in 0..4) {
            if ((top shr i) and 1 == 1) {
                chk = chk xor generator[i]
            }
        }
    }
    return chk
}
