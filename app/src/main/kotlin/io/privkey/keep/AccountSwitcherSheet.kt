package io.privkey.keep

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.privkey.keep.uniffi.ShareMetadataInfo

data class AccountInfo(
    val groupPubkeyHex: String,
    val name: String,
    val shareIndex: UShort,
    val threshold: UShort,
    val totalShares: UShort
)

internal fun ShareMetadataInfo.toAccountInfo() = AccountInfo(
    groupPubkeyHex = groupPubkey.joinToString("") { "%02x".format(it.toInt() and 0xFF) },
    name = name,
    shareIndex = identifier,
    threshold = threshold,
    totalShares = totalShares
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccountSwitcherSheet(
    accounts: List<AccountInfo>,
    activeAccountKey: String?,
    onSwitchAccount: (AccountInfo) -> Unit,
    onDeleteAccount: (AccountInfo) -> Unit,
    onImportAccount: () -> Unit,
    onImportNsec: () -> Unit,
    onDismiss: () -> Unit
) {
    var deleteTarget by remember { mutableStateOf<AccountInfo?>(null) }

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 32.dp)
        ) {
            Text(
                text = "Accounts",
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)
            )

            accounts.forEach { account ->
                val isActive = account.groupPubkeyHex == activeAccountKey
                AccountRow(
                    account = account,
                    isActive = isActive,
                    onClick = {
                        if (!isActive) onSwitchAccount(account)
                    },
                    onDelete = { deleteTarget = account }
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            TextButton(
                onClick = onImportAccount,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                Text("Import FROST Share")
            }

            TextButton(
                onClick = onImportNsec,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                Text("Import nsec")
            }
        }
    }

    deleteTarget?.let { target ->
        val isActive = target.groupPubkeyHex == activeAccountKey
        val isOnlyAccount = accounts.size == 1
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text(if (isOnlyAccount) "Cannot Delete Account" else "Delete Account?") },
            text = {
                Column {
                    if (isOnlyAccount) {
                        Text("You cannot delete your only account. Import another account first before removing this one.")
                    } else {
                        Text("This will permanently delete \"${target.name}\" and its FROST share from this device.")
                        if (isActive) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                "This is your active account. You will need to switch to another account or import a new share.",
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (!isOnlyAccount) {
                            onDeleteAccount(target)
                            deleteTarget = null
                        }
                    },
                    enabled = !isOnlyAccount
                ) {
                    Text("Delete", color = if (isOnlyAccount) MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f) else MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) {
                    Text(if (isOnlyAccount) "OK" else "Cancel")
                }
            }
        )
    }
}

@Composable
private fun AccountRow(
    account: AccountInfo,
    isActive: Boolean,
    onClick: () -> Unit,
    onDelete: () -> Unit
) {
    val colors = MaterialTheme.colorScheme

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 24.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = account.name,
                    style = MaterialTheme.typography.titleMedium
                )
                if (isActive) {
                    Spacer(modifier = Modifier.width(8.dp))
                    Badge(containerColor = colors.primary) {
                        Text("ACTIVE", modifier = Modifier.padding(horizontal = 2.dp))
                    }
                }
            }
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = "Share ${account.shareIndex} of ${account.totalShares} · Threshold ${account.threshold}",
                style = MaterialTheme.typography.bodySmall,
                color = colors.onSurfaceVariant
            )
            Text(
                text = formatPubkeyDisplay(account.groupPubkeyHex),
                style = MaterialTheme.typography.bodySmall,
                color = colors.onSurfaceVariant
            )
        }

        IconButton(onClick = onDelete) {
            Icon(
                Icons.Default.Delete,
                contentDescription = "Delete",
                tint = colors.onSurfaceVariant
            )
        }
    }
}
