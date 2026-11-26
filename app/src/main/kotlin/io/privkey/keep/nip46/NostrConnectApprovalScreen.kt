package io.privkey.keep.nip46

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.privkey.keep.R
import io.privkey.keep.uniffi.NostrConnectInfo
import io.privkey.keep.uniffi.formatPubkeyDisplay

/** Shows a nostrconnect request as the core read it. Nothing here decides what is granted. */
@Composable
internal fun NostrConnectApprovalScreen(
    info: NostrConnectInfo,
    onApprove: (onComplete: (Boolean) -> Unit) -> Unit,
    onReject: () -> Unit,
) {
    var isLoading by remember { mutableStateOf(false) }
    val name = info.name?.let(::sanitizeDisplayName) ?: stringResource(R.string.connections_nostrconnect_unnamed)

    Column(
        modifier = Modifier.fillMaxSize().statusBarsPadding().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(stringResource(R.string.connections_nostrconnect_title), style = MaterialTheme.typography.headlineMedium)
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            stringResource(R.string.connections_nostrconnect_from, name),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Surface(color = MaterialTheme.colorScheme.tertiaryContainer, shape = MaterialTheme.shapes.small, modifier = Modifier.fillMaxWidth()) {
            Text(
                stringResource(R.string.connections_nostrconnect_description),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onTertiaryContainer,
                modifier = Modifier.padding(12.dp),
            )
        }
        Spacer(modifier = Modifier.height(16.dp))
        Card(modifier = Modifier.fillMaxWidth().weight(1f, fill = false)) {
            Column(modifier = Modifier.padding(16.dp).verticalScroll(rememberScrollState())) {
                Nip46DetailRow(stringResource(R.string.connections_nostrconnect_client_pubkey), formatPubkeyDisplay(info.clientPubkey))
                info.url?.let {
                    Spacer(modifier = Modifier.height(12.dp))
                    Nip46DetailRow(stringResource(R.string.connections_nostrconnect_url), sanitizeDisplayName(it))
                }
                Spacer(modifier = Modifier.height(12.dp))
                Label(stringResource(R.string.connections_nostrconnect_relays))
                info.relays.forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
                Spacer(modifier = Modifier.height(12.dp))
                Label(stringResource(R.string.connections_nostrconnect_requested_permissions))
                Spacer(modifier = Modifier.height(4.dp))
                val requested = requestedPermissions(info.requestedPermissions)
                if (requested.isEmpty()) {
                    Text(stringResource(R.string.connections_nostrconnect_default_permissions), style = MaterialTheme.typography.bodyMedium)
                }
                requested.forEach { Text(formatNip46Method(it), style = MaterialTheme.typography.bodyMedium) }
            }
        }
        Spacer(modifier = Modifier.height(24.dp))
        if (isLoading) {
            CircularProgressIndicator()
        } else {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                OutlinedButton(onClick = onReject, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.connections_nostrconnect_reject))
                }
                Button(
                    onClick = {
                        isLoading = true
                        onApprove { connected -> if (!connected) isLoading = false }
                    },
                    modifier = Modifier.weight(1f),
                ) {
                    Text(stringResource(R.string.connections_nostrconnect_connect))
                }
            }
        }
    }
}

@Composable
private fun Label(text: String) {
    Text(text, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

/**
 * The methods the request's `perms` names, for display only. Kinds are left out, since the core
 * grants a method for every kind. Stopgap until the core returns the grant it will give.
 */
internal fun requestedPermissions(perms: String?): List<String> =
    perms.orEmpty().split(',').map { it.trim().substringBefore(':').trim() }.filter { it.isNotEmpty() }
        .map(::sanitizeDisplayName).distinct()
