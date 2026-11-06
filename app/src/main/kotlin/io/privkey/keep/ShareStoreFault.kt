package io.privkey.keep

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.privkey.keep.ui.components.KeepCard
import io.privkey.keep.uniffi.ShareStoreStatus

/** The accounts whose stored share exists but cannot be read. */
internal fun unreadableGroups(status: ShareStoreStatus): List<String> =
    (status as? ShareStoreStatus.SomeUnreadable)?.groupPubkeys.orEmpty()

/**
 * The groups a retry left unreadable, added to those already known to have failed one, so
 * Remove is offered only for an account that a retry could not bring back. A group that
 * reads again is dropped from the set.
 */
internal fun afterRetry(failedBefore: Set<String>, retried: Collection<String>, now: ShareStoreStatus): Set<String> {
    val stillUnreadable = unreadableGroups(now).toSet()
    return (failedBefore + retried).filterTo(mutableSetOf()) { it in stillUnreadable }
}

internal fun shortGroup(group: String): String =
    if (group.length > 16) "${group.take(8)}…${group.takeLast(8)}" else group

@Composable
internal fun UnreadableSharesCard(
    groups: List<String>,
    retryFailed: Set<String>,
    retrying: Boolean,
    onRetry: () -> Unit,
    onRemove: (String) -> Unit,
) {
    KeepCard {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                stringResource(R.string.share_unreadable_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.error,
            )
            Text(stringResource(R.string.share_unreadable_text), style = MaterialTheme.typography.bodyMedium)
            groups.forEach { group ->
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        shortGroup(group),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f),
                    )
                    if (group in retryFailed) {
                        TextButton(onClick = { onRemove(group) }, enabled = !retrying) {
                            Text(stringResource(R.string.share_unreadable_remove), color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }
            if (groups.any { it !in retryFailed }) {
                Text(stringResource(R.string.share_unreadable_retry_first), style = MaterialTheme.typography.bodySmall)
            }
            Button(onClick = onRetry, enabled = !retrying) {
                Text(stringResource(R.string.share_unreadable_retry))
            }
        }
    }
}

@Composable
internal fun RemoveUnreadableShareDialog(group: String, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.share_unreadable_remove_title)) },
        text = { Text(stringResource(R.string.share_unreadable_remove_text, shortGroup(group))) },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.share_unreadable_remove), color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.share_unreadable_keep)) }
        },
    )
}

@Composable
internal fun UnreadableShareRemovedDialog(onRestore: () -> Unit, onImport: () -> Unit, onDone: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(stringResource(R.string.share_unreadable_removed_title)) },
        text = { Text(stringResource(R.string.share_unreadable_removed_text)) },
        confirmButton = {
            TextButton(onClick = onRestore) { Text(stringResource(R.string.share_unreadable_restore)) }
        },
        dismissButton = {
            Row {
                TextButton(onClick = onImport) { Text(stringResource(R.string.share_unreadable_import)) }
                TextButton(onClick = onDone) { Text(stringResource(R.string.share_unreadable_done)) }
            }
        },
    )
}

/** Shown instead of the app while the list of stored shares itself cannot be read. */
@Composable
internal fun ShareStoreUnavailableScreen(retrying: Boolean, onRetry: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            stringResource(R.string.share_store_unavailable_title),
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.error,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            stringResource(R.string.share_store_unavailable_text),
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(24.dp))
        Button(onClick = onRetry, enabled = !retrying) {
            Text(stringResource(R.string.share_unreadable_retry))
        }
    }
}
