package io.privkey.keep

import io.privkey.keep.uniffi.hexToNpub
import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.privkey.keep.uniffi.ShareInfo

@Composable
fun ShareDetailsScreen(
    shareInfo: ShareInfo,
    onExport: () -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val npub = remember(shareInfo.groupPubkey) {
        hexToNpub(shareInfo.groupPubkey) ?: ""
    }
    val isNpubValid = npub.isNotBlank()
    val npubCopiedMessage = stringResource(R.string.share_details_npub_copied_toast)

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
            text = stringResource(R.string.share_details_share_of, shareInfo.shareIndex.toInt(), shareInfo.totalShares.toInt()),
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Text(
            text = stringResource(R.string.share_details_threshold, shareInfo.threshold.toInt()),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(32.dp))

        if (isNpubValid) {
            QrCodeDisplay(
                data = npub,
                label = stringResource(R.string.share_details_qr_label),
                onCopied = {
                    Toast.makeText(context, npubCopiedMessage, Toast.LENGTH_SHORT).show()
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
                    text = stringResource(R.string.share_details_invalid_group_pubkey),
                    modifier = Modifier.padding(16.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = stringResource(R.string.share_details_npub_header),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = if (isNpubValid) io.privkey.keep.uniffi.truncateStr(npub, 12u, 8u) else stringResource(R.string.share_details_npub_placeholder),
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
            Text(stringResource(R.string.share_details_export_qr))
        }

        Spacer(modifier = Modifier.height(8.dp))

        OutlinedButton(
            onClick = {
                if (isNpubValid) {
                    copySensitiveText(context, npub)
                    Toast.makeText(context, npubCopiedMessage, Toast.LENGTH_SHORT).show()
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = isNpubValid
        ) {
            Text(stringResource(R.string.share_details_copy_npub))
        }

        Spacer(modifier = Modifier.height(8.dp))

        TextButton(
            onClick = onDismiss,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.back))
        }
    }
}

