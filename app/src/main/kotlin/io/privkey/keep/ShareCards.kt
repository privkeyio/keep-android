package io.privkey.keep

import io.privkey.keep.ui.components.KeepCard
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.privkey.keep.uniffi.ShareInfo

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccountSelectorCard(accountCount: Int, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer
        )
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                pluralStringResource(R.plurals.share_cards_accounts, accountCount, accountCount),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSecondaryContainer
            )
            Text(
                stringResource(R.string.share_cards_switch),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShareInfoCard(info: ShareInfo, onClick: () -> Unit) {
    val isNsec = isNsecKey(info.shareIndex, info.threshold, info.totalShares)

    Card(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(info.name, style = MaterialTheme.typography.titleLarge)
            Spacer(modifier = Modifier.height(4.dp))
            AccountTypeBadge(isNsec = isNsec)
            Spacer(modifier = Modifier.height(8.dp))
            if (!isNsec) {
                Text(stringResource(R.string.share_cards_share_of, info.shareIndex.toInt(), info.totalShares.toInt()))
                Text(stringResource(R.string.share_cards_threshold, info.threshold.toInt()))
                Spacer(modifier = Modifier.height(8.dp))
            }
            Text(
                stringResource(R.string.share_cards_group, io.privkey.keep.uniffi.truncateStr(info.groupPubkey, 8u, 6u)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                stringResource(R.string.share_cards_tap_for_qr),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary
            )
        }
    }
}

@Composable
fun NoShareCard(
    onImport: () -> Unit,
    onImportNsec: () -> Unit,
    onCreateAccount: () -> Unit,
    onRecoverMnemonic: () -> Unit,
    onCreateGroup: () -> Unit
) {
    KeepCard(contentPadding = PaddingValues(0.dp)) {
        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(stringResource(R.string.share_cards_no_key_stored))
            Spacer(modifier = Modifier.height(16.dp))
            Button(onClick = onCreateAccount, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.share_cards_create_account))
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(onClick = onRecoverMnemonic, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.share_cards_import_seed))
            }
            Spacer(modifier = Modifier.height(8.dp))
            HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
            Spacer(modifier = Modifier.height(4.dp))
            OutlinedButton(onClick = onImport, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.share_cards_import_frost))
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(onClick = onImportNsec, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.share_cards_import_nsec))
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(onClick = onCreateGroup, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.share_cards_create_group))
            }
        }
    }
}

@Composable
fun ErrorScreen(message: String) {
    Box(modifier = Modifier.fillMaxSize().statusBarsPadding(), contentAlignment = Alignment.Center) {
        Text(message, color = MaterialTheme.colorScheme.error)
    }
}
