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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.privkey.keep.uniffi.ShareMetadataInfo

data class AccountInfo(
    val groupPubkeyHex: String,
    val name: String,
    val shareIndex: UShort,
    val threshold: UShort,
    val totalShares: UShort
)

fun isNsecKey(shareIndex: UShort, threshold: UShort, totalShares: UShort): Boolean =
    shareIndex == 1.toUShort() && threshold == 1.toUShort() && totalShares == 1.toUShort()

val AccountInfo.isNsecKey: Boolean
    get() = isNsecKey(shareIndex, threshold, totalShares)

val AccountInfo.typeBadgeText: String
    get() = if (isNsecKey) "nsec" else "FROST Share"

@Composable
fun AccountTypeBadge(isNsec: Boolean) {
    Badge(
        containerColor = if (isNsec)
            MaterialTheme.colorScheme.tertiary
        else
            MaterialTheme.colorScheme.secondary
    ) {
        Text(
            if (isNsec) stringResource(R.string.account_badge_nsec) else stringResource(R.string.account_badge_frost_share),
            modifier = Modifier.padding(horizontal = 2.dp)
        )
    }
}

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
    onCreateAccount: () -> Unit,
    onCreateGroup: () -> Unit,
    onRecoverMnemonic: () -> Unit,
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
                text = stringResource(R.string.account_sheet_title),
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
                onClick = onCreateAccount,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                Text(stringResource(R.string.account_create))
            }

            TextButton(
                onClick = onCreateGroup,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                Text(stringResource(R.string.share_cards_create_group))
            }

            TextButton(
                onClick = onRecoverMnemonic,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                Text(stringResource(R.string.account_import_seed_words))
            }

            TextButton(
                onClick = onImportAccount,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                Text(stringResource(R.string.account_import_frost_share))
            }

            TextButton(
                onClick = onImportNsec,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                Text(stringResource(R.string.account_import_nsec))
            }
        }
    }

    deleteTarget?.let { target ->
        val isActive = target.groupPubkeyHex == activeAccountKey
        val isOnlyAccount = accounts.size == 1
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = {
                Text(
                    if (isOnlyAccount) stringResource(R.string.account_delete_cannot_title)
                    else stringResource(R.string.account_delete_confirm_title)
                )
            },
            text = {
                Column {
                    if (isOnlyAccount) {
                        Text(stringResource(R.string.account_delete_only_text))
                    } else {
                        Text(
                            if (target.isNsecKey)
                                stringResource(R.string.account_delete_nsec_text, target.name)
                            else
                                stringResource(R.string.account_delete_frost_text, target.name)
                        )
                        if (isActive) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                stringResource(R.string.account_delete_active_warning),
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
                    Text(stringResource(R.string.account_delete_button), color = color)
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) {
                    Text(
                        if (isOnlyAccount) stringResource(R.string.account_ok)
                        else stringResource(R.string.account_cancel)
                    )
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
        title = { Text(stringResource(R.string.account_rename_title)) },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { if (it.length <= MAX_ACCOUNT_NAME_LENGTH) name = it },
                label = { Text(stringResource(R.string.account_rename_label)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(trimmedName) },
                enabled = trimmedName.isNotBlank() && trimmedName != currentName.trim()
            ) {
                Text(stringResource(R.string.account_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.account_cancel))
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
    val npubCopiedMessage = stringResource(R.string.account_npub_copied)
    val npubCopyFailedMessage = stringResource(R.string.account_npub_copy_failed)

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
                contentDescription = stringResource(R.string.account_row_active_cd),
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
            AccountTypeBadge(isNsec = account.isNsecKey)
            Spacer(modifier = Modifier.height(2.dp))
            if (!account.isNsecKey) {
                Text(
                    text = stringResource(
                        R.string.account_row_share_summary,
                        account.shareIndex.toInt(),
                        account.totalShares.toInt(),
                        account.threshold.toInt()
                    ),
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
                Toast.makeText(context, npubCopiedMessage, Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(context, npubCopyFailedMessage, Toast.LENGTH_SHORT).show()
            }
        }) {
            Icon(
                Icons.Default.ContentCopy,
                contentDescription = stringResource(R.string.account_copy_npub_cd),
                tint = colors.onSurfaceVariant
            )
        }

        IconButton(onClick = onEdit) {
            Icon(
                Icons.Default.Edit,
                contentDescription = stringResource(R.string.account_edit_name_cd),
                tint = colors.onSurfaceVariant
            )
        }

        IconButton(onClick = onDelete) {
            Icon(
                Icons.Default.Delete,
                contentDescription = stringResource(R.string.account_delete_cd),
                tint = colors.onSurfaceVariant
            )
        }
    }
}
