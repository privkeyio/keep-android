package io.privkey.keep

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.privkey.keep.uniffi.BackupInfo
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.backupMinPassphraseLength
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalDate
import java.time.format.DateTimeFormatter

private sealed class BackupState {
    data object Idle : BackupState()
    data object Creating : BackupState()
    data class Created(val data: ByteArray) : BackupState()
    data class Error(val message: String) : BackupState()
}

private sealed class RestoreState {
    data object Idle : RestoreState()
    data class FileSelected(val data: ByteArray, val fileName: String) : RestoreState()
    data object Verifying : RestoreState()
    data class Verified(val data: ByteArray, val info: BackupInfo) : RestoreState()
    data object Restoring : RestoreState()
    data class Restored(val info: BackupInfo) : RestoreState()
    data class Error(val message: String) : RestoreState()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackupRestoreScreen(
    keepMobile: KeepMobile,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val minPassphraseLength = remember { backupMinPassphraseLength().toInt() }

    var backupPassphrase by remember { mutableStateOf("") }
    var backupPassphraseConfirm by remember { mutableStateOf("") }
    var backupState by remember { mutableStateOf<BackupState>(BackupState.Idle) }

    var restorePassphrase by remember { mutableStateOf("") }
    var restoreState by remember { mutableStateOf<RestoreState>(RestoreState.Idle) }
    var showRestoreConfirmDialog by remember { mutableStateOf(false) }

    val saveFileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        if (uri != null) {
            val data = (backupState as? BackupState.Created)?.data ?: return@rememberLauncherForActivityResult
            try {
                context.contentResolver.openOutputStream(uri)?.use { it.write(data) }
                Toast.makeText(context, "Backup saved", Toast.LENGTH_SHORT).show()
                backupState = BackupState.Idle
                backupPassphrase = ""
                backupPassphraseConfirm = ""
            } catch (e: Exception) {
                backupState = BackupState.Error("Failed to save: ${e.message}")
            }
        }
    }

    val openFileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            try {
                val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                if (bytes != null) {
                    restoreState = RestoreState.FileSelected(bytes, uri.lastPathSegment ?: "backup")
                    restorePassphrase = ""
                }
            } catch (e: Exception) {
                restoreState = RestoreState.Error("Failed to read file: ${e.message}")
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Vault Backup") },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text("Create Backup", style = MaterialTheme.typography.titleLarge)

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    OutlinedTextField(
                        value = backupPassphrase,
                        onValueChange = { backupPassphrase = it },
                        label = { Text("Passphrase") },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = backupPassphraseConfirm,
                        onValueChange = { backupPassphraseConfirm = it },
                        label = { Text("Confirm passphrase") },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    val passphraseError = when {
                        backupPassphrase.isNotEmpty() && backupPassphrase.length < minPassphraseLength ->
                            "Passphrase must be at least $minPassphraseLength characters"
                        backupPassphraseConfirm.isNotEmpty() && backupPassphrase != backupPassphraseConfirm ->
                            "Passphrases do not match"
                        else -> null
                    }
                    passphraseError?.let {
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    val canCreate = backupPassphrase.length >= minPassphraseLength &&
                        backupPassphrase == backupPassphraseConfirm &&
                        backupState !is BackupState.Creating

                    Button(
                        onClick = {
                            backupState = BackupState.Creating
                            scope.launch {
                                try {
                                    val data = withContext(Dispatchers.IO) {
                                        keepMobile.createBackup(backupPassphrase)
                                    }
                                    backupState = BackupState.Created(data)
                                    val date = LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE)
                                    saveFileLauncher.launch("keep-backup-$date.kbak")
                                } catch (e: Exception) {
                                    backupState = BackupState.Error(e.message ?: "Backup failed")
                                }
                            }
                        },
                        enabled = canCreate,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (backupState is BackupState.Creating) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp,
                                color = MaterialTheme.colorScheme.onPrimary
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        Text("Create Backup")
                    }

                    if (backupState is BackupState.Error) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            (backupState as BackupState.Error).message,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }

            HorizontalDivider()

            Text("Restore Backup", style = MaterialTheme.typography.titleLarge)

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Button(
                        onClick = { openFileLauncher.launch(arrayOf("*/*")) },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Select Backup File")
                    }

                    val currentRestoreState = restoreState
                    when (currentRestoreState) {
                        is RestoreState.FileSelected, is RestoreState.Verified -> {
                            val fileName = when (currentRestoreState) {
                                is RestoreState.FileSelected -> currentRestoreState.fileName
                                is RestoreState.Verified -> "Verified"
                                else -> ""
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                "File: $fileName",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )

                            Spacer(modifier = Modifier.height(8.dp))
                            OutlinedTextField(
                                value = restorePassphrase,
                                onValueChange = { restorePassphrase = it },
                                label = { Text("Backup passphrase") },
                                visualTransformation = PasswordVisualTransformation(),
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )

                            Spacer(modifier = Modifier.height(12.dp))

                            if (currentRestoreState is RestoreState.FileSelected) {
                                OutlinedButton(
                                    onClick = {
                                        restoreState = RestoreState.Verifying
                                        scope.launch {
                                            try {
                                                val info = withContext(Dispatchers.IO) {
                                                    keepMobile.verifyBackup(
                                                        currentRestoreState.data,
                                                        restorePassphrase
                                                    )
                                                }
                                                restoreState = RestoreState.Verified(
                                                    currentRestoreState.data,
                                                    info
                                                )
                                            } catch (e: Exception) {
                                                restoreState = RestoreState.Error(
                                                    e.message ?: "Verification failed"
                                                )
                                            }
                                        }
                                    },
                                    enabled = restorePassphrase.length >= minPassphraseLength,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text("Verify")
                                }
                            }

                            if (currentRestoreState is RestoreState.Verified) {
                                BackupSummaryCard(currentRestoreState.info)
                                Spacer(modifier = Modifier.height(12.dp))
                                Button(
                                    onClick = { showRestoreConfirmDialog = true },
                                    modifier = Modifier.fillMaxWidth(),
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = MaterialTheme.colorScheme.error
                                    )
                                ) {
                                    Text("Restore")
                                }
                            }
                        }

                        is RestoreState.Verifying -> {
                            Spacer(modifier = Modifier.height(12.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.Center
                            ) {
                                CircularProgressIndicator(modifier = Modifier.size(24.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Verifying...")
                            }
                        }

                        is RestoreState.Restoring -> {
                            Spacer(modifier = Modifier.height(12.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.Center
                            ) {
                                CircularProgressIndicator(modifier = Modifier.size(24.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Restoring...")
                            }
                        }

                        is RestoreState.Restored -> {
                            Spacer(modifier = Modifier.height(12.dp))
                            BackupSummaryCard(currentRestoreState.info)
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                "Restore complete",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }

                        is RestoreState.Error -> {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                currentRestoreState.message,
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodySmall
                            )
                        }

                        is RestoreState.Idle -> {}
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }

    if (showRestoreConfirmDialog) {
        val verifiedState = restoreState as? RestoreState.Verified
        AlertDialog(
            onDismissRequest = { showRestoreConfirmDialog = false },
            title = { Text("Restore Backup?") },
            text = { Text("This will import all keys, shares, and settings from the backup. Existing data with the same keys will be overwritten.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        showRestoreConfirmDialog = false
                        if (verifiedState != null) {
                            restoreState = RestoreState.Restoring
                            scope.launch {
                                try {
                                    val info = withContext(Dispatchers.IO) {
                                        keepMobile.restoreBackup(
                                            verifiedState.data,
                                            restorePassphrase
                                        )
                                    }
                                    restoreState = RestoreState.Restored(info)
                                    Toast.makeText(context, "Backup restored", Toast.LENGTH_SHORT).show()
                                } catch (e: Exception) {
                                    restoreState = RestoreState.Error(
                                        e.message ?: "Restore failed"
                                    )
                                }
                            }
                        }
                    }
                ) {
                    Text("Restore", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showRestoreConfirmDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Composable
private fun BackupSummaryCard(info: BackupInfo) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text("Backup Summary", style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(4.dp))
            Text("Keys: ${info.keyCount}", style = MaterialTheme.typography.bodySmall)
            Text("Shares: ${info.shareCount}", style = MaterialTheme.typography.bodySmall)
            Text("Descriptors: ${info.descriptorCount}", style = MaterialTheme.typography.bodySmall)
            Text("Created: ${info.createdAt}", style = MaterialTheme.typography.bodySmall)
        }
    }
}
