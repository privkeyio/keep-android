package io.privkey.keep

import android.widget.Toast
import io.privkey.keep.uniffi.formatPubkeyDisplay
import io.privkey.keep.uniffi.hexToNpub
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.RadioButtonChecked
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.privkey.keep.uniffi.ShareMetadataInfo

data class AccountInfo(
    val groupPubkeyHex: String,
    val name: String,
    val shareIndex: UShort,
    val threshold: UShort,
    val totalShares: UShort
)

val AccountInfo.isNsecKey: Boolean
    get() = shareIndex == 1.toUShort() && threshold == 1.toUShort() && totalShares == 1.toUShort()

val AccountInfo.typeBadgeText: String
    get() = if (isNsecKey) "nsec" else "FROST Share"

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
    onRenameAccount: (AccountInfo, String) -> Unit,
    onImportAccount: () -> Unit,
    onImportNsec: () -> Unit,
    onDismiss: () -> Unit
) {
    var deleteTarget by remember { mutableStateOf<AccountInfo?>(null) }
    var editTarget by remember { mutableStateOf<AccountInfo?>(null) }

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
                    onEdit = { editTarget = account },
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
                        Text("This will permanently delete \"${target.name}\" and its ${if (target.isNsecKey) "nsec key" else "FROST share"} from this device.")
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
                        onDeleteAccount(target)
                        deleteTarget = null
                    },
                    enabled = !isOnlyAccount
                ) {
                    val color = if (isOnlyAccount) {
                        MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
                    } else {
                        MaterialTheme.colorScheme.error
                    }
                    Text("Delete", color = color)
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) {
                    Text(if (isOnlyAccount) "OK" else "Cancel")
                }
            }
        )
    }

    editTarget?.let { target ->
        RenameAccountDialog(
            currentName = target.name,
            onConfirm = { newName ->
                onRenameAccount(target, newName)
                editTarget = null
            },
            onDismiss = { editTarget = null }
        )
    }
}

@Composable
private fun RenameAccountDialog(
    currentName: String,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit
) {
    var name by remember { mutableStateOf(currentName) }
    val trimmedName = name.trim()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Rename Account") },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { if (it.length <= 64) name = it },
                label = { Text("Account name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(trimmedName) },
                enabled = trimmedName.isNotBlank()
            ) {
                Text("Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
private fun AccountRow(
    account: AccountInfo,
    isActive: Boolean,
    onClick: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit
) {
    val colors = MaterialTheme.colorScheme
    val context = LocalContext.current

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 24.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (isActive) {
            Icon(
                imageVector = Icons.Default.RadioButtonChecked,
                contentDescription = "Active account",
                tint = colors.primary,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
        } else {
            Spacer(modifier = Modifier.width(36.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = account.name,
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(modifier = Modifier.height(2.dp))
            Badge(
                containerColor = if (account.isNsecKey) colors.tertiary else colors.secondary
            ) {
                Text(
                    account.typeBadgeText,
                    modifier = Modifier.padding(horizontal = 2.dp)
                )
            }
            Spacer(modifier = Modifier.height(2.dp))
            if (!account.isNsecKey) {
                Text(
                    text = "Share ${account.shareIndex} of ${account.totalShares} \u00b7 Threshold ${account.threshold}",
                    style = MaterialTheme.typography.bodySmall,
                    color = colors.onSurfaceVariant
                )
            }
            Text(
                text = formatPubkeyDisplay(account.groupPubkeyHex),
                style = MaterialTheme.typography.bodySmall,
                color = colors.onSurfaceVariant
            )
        }

        IconButton(onClick = {
            val npub = hexToNpub(account.groupPubkeyHex)
            if (npub != null) {
                copyPublicText(context, npub)
                Toast.makeText(context, "npub copied", Toast.LENGTH_SHORT).show()
            }
        }) {
            Icon(
                Icons.Default.ContentCopy,
                contentDescription = "Copy npub",
                tint = colors.onSurfaceVariant
            )
        }

        IconButton(onClick = onEdit) {
            Icon(
                Icons.Default.Edit,
                contentDescription = "Edit name",
                tint = colors.onSurfaceVariant
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
