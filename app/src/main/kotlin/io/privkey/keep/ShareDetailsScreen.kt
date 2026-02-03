package io.privkey.keep

import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.privkey.keep.uniffi.ShareInfo

private const val BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

@Composable
fun ShareDetailsScreen(
    shareInfo: ShareInfo,
    onExport: () -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val npub = remember(shareInfo.groupPubkey) {
        hexToNpub(shareInfo.groupPubkey)
    }
    val isNpubValid = npub.isNotBlank()

    DisposableEffect(Unit) {
        setSecureScreen(context, true)
        onDispose {
            setSecureScreen(context, false)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = shareInfo.name,
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Share ${shareInfo.shareIndex} of ${shareInfo.totalShares}",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Text(
            text = "Threshold: ${shareInfo.threshold}",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(32.dp))

        if (isNpubValid) {
            QrCodeDisplay(
                data = npub,
                label = "Group Public Key (npub)",
                onCopied = {
                    Toast.makeText(context, "npub copied", Toast.LENGTH_SHORT).show()
                }
            )
        } else {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer
                )
            ) {
                Text(
                    text = "Invalid group public key",
                    modifier = Modifier.padding(16.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "npub",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = if (isNpubValid) npub.take(24) + "..." + npub.takeLast(8) else "---",
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = onExport,
            modifier = Modifier.fillMaxWidth(),
            enabled = isNpubValid
        ) {
            Text("Export Share as QR")
        }

        Spacer(modifier = Modifier.height(8.dp))

        OutlinedButton(
            onClick = {
                if (isNpubValid) {
                    copySensitiveText(context, npub)
                    Toast.makeText(context, "npub copied", Toast.LENGTH_SHORT).show()
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = isNpubValid
        ) {
            Text("Copy npub")
        }

        Spacer(modifier = Modifier.height(8.dp))

        TextButton(
            onClick = onDismiss,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Back")
        }
    }
}

private val HEX_REGEX = Regex("^[0-9a-fA-F]+$")

private fun hexToNpub(hex: String): String {
    if (hex.isEmpty() || hex.length % 2 != 0 || !HEX_REGEX.matches(hex)) {
        return ""
    }
    return try {
        val bytes = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        bytesToNpub(bytes)
    } catch (_: Exception) {
        ""
    }
}

private fun bytesToNpub(pubkey: ByteArray): String {
    if (pubkey.size != 32) return ""
    val hrp = "npub"
    val data = convertBits(pubkey.toList(), 8, 5, true)
    return bech32Encode(hrp, data)
}

private fun convertBits(data: List<Byte>, fromBits: Int, toBits: Int, pad: Boolean): List<Int> {
    var acc = 0
    var bits = 0
    val result = mutableListOf<Int>()
    val maxV = (1 shl toBits) - 1

    for (value in data) {
        val v = value.toInt() and 0xFF
        acc = (acc shl fromBits) or v
        bits += fromBits
        while (bits >= toBits) {
            bits -= toBits
            result.add((acc shr bits) and maxV)
        }
    }

    if (pad && bits > 0) {
        result.add((acc shl (toBits - bits)) and maxV)
    }

    return result
}

private fun bech32Encode(hrp: String, data: List<Int>): String {
    val checksum = bech32CreateChecksum(hrp, data)
    val combined = data + checksum
    val encoded = StringBuilder(hrp)
    encoded.append('1')
    for (d in combined) {
        encoded.append(BECH32_CHARSET[d])
    }
    return encoded.toString()
}

private fun bech32CreateChecksum(hrp: String, data: List<Int>): List<Int> {
    val values = bech32HrpExpand(hrp) + data + listOf(0, 0, 0, 0, 0, 0)
    val polymod = bech32Polymod(values) xor 1
    return (0..5).map { (polymod shr (5 * (5 - it))) and 31 }
}

private fun bech32HrpExpand(hrp: String): List<Int> {
    return hrp.map { it.code shr 5 } + 0 + hrp.map { it.code and 31 }
}

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
