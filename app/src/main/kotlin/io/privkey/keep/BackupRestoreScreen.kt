package io.privkey.keep

import android.util.Log
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.BackupInfo
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.backupMinPassphraseLength
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.util.UUID
import javax.crypto.Cipher

private const val MAX_BACKUP_FILE_SIZE = 10L * 1024 * 1024 // 10 MB

private sealed class BackupState {
    data object Idle : BackupState()
    data object Creating : BackupState()
    class Created(val data: ByteArray) : BackupState()
    data class Error(val message: String) : BackupState()
}

private sealed class RestoreState {
    data object Idle : RestoreState()
    class FileSelected(val data: ByteArray, val fileName: String) : RestoreState()
    data object Verifying : RestoreState()
    class Verified(val data: ByteArray, val info: BackupInfo, val fileName: String) : RestoreState()
    data object Restoring : RestoreState()
    data class Restored(val info: BackupInfo) : RestoreState()
    data class Error(val message: String) : RestoreState()
}

private fun clearByteArray(bytes: ByteArray) = bytes.fill(0)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackupRestoreScreen(
    keepMobile: KeepMobile,
    storage: AndroidKeystoreStorage,
    onGetCipher: () -> Cipher?,
    onBiometricAuth: (Cipher, (Cipher?) -> Unit) -> Unit,
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
    var confirmingRestore by remember { mutableStateOf<RestoreState.Verified?>(null) }
    val activeRequestIds = remember { mutableStateListOf<String>() }

    DisposableEffect(context) {
        setSecureScreen(context, true)
        onDispose {
            setSecureScreen(context, false)
            backupPassphrase = ""
            backupPassphraseConfirm = ""
            restorePassphrase = ""
            (backupState as? BackupState.Created)?.let { clearByteArray(it.data) }
            when (val rs = restoreState) {
                is RestoreState.FileSelected -> clearByteArray(rs.data)
                is RestoreState.Verified -> clearByteArray(rs.data)
                else -> {}
            }
            for (id in activeRequestIds) {
                storage.clearPendingCipher(id)
            }
            activeRequestIds.clear()
        }
    }

    fun requireBiometricAuth(onAuthed: (authedCipher: Cipher) -> Unit) {
        val cipher = onGetCipher()
        if (cipher == null) {
            Toast.makeText(context, "Authentication unavailable", Toast.LENGTH_SHORT).show()
            return
        }
        onBiometricAuth(cipher) { authedCipher ->
            if (authedCipher != null) onAuthed(authedCipher)
        }
    }

    val saveFileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        if (uri != null) {
            val created = backupState as? BackupState.Created ?: return@rememberLauncherForActivityResult
            try {
                val outputStream = context.contentResolver.openOutputStream(uri)
                if (outputStream == null) {
                    backupState = BackupState.Error("Failed to save backup")
                    return@rememberLauncherForActivityResult
                }
                outputStream.use { it.write(created.data) }
                clearByteArray(created.data)
                Toast.makeText(context, "Backup saved", Toast.LENGTH_SHORT).show()
                backupState = BackupState.Idle
                backupPassphrase = ""
                backupPassphraseConfirm = ""
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.e("BackupRestore", "Failed to save backup", e)
                backupState = BackupState.Error("Failed to save backup")
            }
        } else {
            (backupState as? BackupState.Created)?.let { clearByteArray(it.data) }
            backupState = BackupState.Idle
        }
    }

    val openFileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            try {
                val size = context.contentResolver.openAssetFileDescriptor(uri, "r")?.use { it.length } ?: -1
                if (size > MAX_BACKUP_FILE_SIZE) {
                    restoreState = RestoreState.Error("File too large (max ${MAX_BACKUP_FILE_SIZE / 1024 / 1024} MB)")
                    return@rememberLauncherForActivityResult
                }
                val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                if (bytes == null) {
                    restoreState = RestoreState.Error("Failed to read file")
                    return@rememberLauncherForActivityResult
                }
                if (bytes.size > MAX_BACKUP_FILE_SIZE) {
                    clearByteArray(bytes)
                    restoreState = RestoreState.Error("File too large (max ${MAX_BACKUP_FILE_SIZE / 1024 / 1024} MB)")
                    return@rememberLauncherForActivityResult
                }
                restoreState = RestoreState.FileSelected(bytes, uri.lastPathSegment ?: "backup")
                restorePassphrase = ""
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.e("BackupRestore", "Failed to read file", e)
                restoreState = RestoreState.Error("Failed to read file")
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
                            requireBiometricAuth { authedCipher ->
                                val requestId = UUID.randomUUID().toString()
                                backupState = BackupState.Creating
                                val passphrase = backupPassphrase
                                scope.launch {
                                    try {
                                        storage.setPendingCipher(requestId, authedCipher)
                                        activeRequestIds.add(requestId)
                                        val data = withContext(Dispatchers.IO) {
                                            try {
                                                storage.setRequestIdContext(requestId)
                                                keepMobile.createBackup(passphrase)
                                            } finally {
                                                storage.clearRequestIdContext()
                                            }
                                        }
                                        backupState = BackupState.Created(data)
                                        val date = LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE)
                                        saveFileLauncher.launch("keep-backup-$date.kbak")
                                    } catch (e: Exception) {
                                        if (BuildConfig.DEBUG) Log.e("BackupRestore", "Backup failed", e)
                                        backupState = BackupState.Error("Backup failed")
                                    } finally {
                                        storage.clearPendingCipher(requestId)
                                        activeRequestIds.remove(requestId)
                                    }
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

                    val backupError = backupState as? BackupState.Error
                    if (backupError != null) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            backupError.message,
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
                        onClick = { openFileLauncher.launch(arrayOf("application/octet-stream", "*/*")) },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Select Backup File")
                    }

                    when (val currentRestoreState = restoreState) {
                        is RestoreState.FileSelected -> {
                            RestoreFileInfo(currentRestoreState.fileName, restorePassphrase) {
                                restorePassphrase = it
                            }
                            Spacer(modifier = Modifier.height(12.dp))
                            OutlinedButton(
                                onClick = {
                                    restoreState = RestoreState.Verifying
                                    val passphrase = restorePassphrase
                                    scope.launch {
                                        try {
                                            val info = withContext(Dispatchers.IO) {
                                                keepMobile.verifyBackup(currentRestoreState.data, passphrase)
                                            }
                                            restoreState = RestoreState.Verified(currentRestoreState.data, info, currentRestoreState.fileName)
                                        } catch (e: Exception) {
                                            if (BuildConfig.DEBUG) Log.e("BackupRestore", "Verification failed", e)
                                            clearByteArray(currentRestoreState.data)
                                            restoreState = RestoreState.Error("Verification failed")
                                        }
                                    }
                                },
                                enabled = restorePassphrase.length >= minPassphraseLength,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Verify")
                            }
                        }

                        is RestoreState.Verified -> {
                            RestoreFileInfo(currentRestoreState.fileName, restorePassphrase) {
                                restorePassphrase = it
                            }
                            Spacer(modifier = Modifier.height(12.dp))
                            BackupSummaryCard(currentRestoreState.info)
                            Spacer(modifier = Modifier.height(12.dp))
                            Button(
                                onClick = { confirmingRestore = currentRestoreState },
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = MaterialTheme.colorScheme.error
                                )
                            ) {
                                Text("Restore")
                            }
                        }

                        is RestoreState.Verifying -> {
                            RestoreProgressRow("Verifying...")
                        }

                        is RestoreState.Restoring -> {
                            RestoreProgressRow("Restoring...")
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

    val verifiedState = confirmingRestore
    if (verifiedState != null) {
        AlertDialog(
            onDismissRequest = { confirmingRestore = null },
            title = { Text("Restore Backup?") },
            text = {
                Text(
                    "This will import all keys, shares, and settings from the backup." +
                        " Existing data with the same keys will be overwritten."
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmingRestore = null
                        requireBiometricAuth { authedCipher ->
                            val requestId = UUID.randomUUID().toString()
                            restoreState = RestoreState.Restoring
                            val passphrase = restorePassphrase
                            scope.launch {
                                try {
                                    storage.setPendingCipher(requestId, authedCipher)
                                    activeRequestIds.add(requestId)
                                    val info = withContext(Dispatchers.IO) {
                                        try {
                                            storage.setRequestIdContext(requestId)
                                            keepMobile.restoreBackup(
                                                verifiedState.data,
                                                passphrase
                                            )
                                        } finally {
                                            storage.clearRequestIdContext()
                                        }
                                    }
                                    clearByteArray(verifiedState.data)
                                    restoreState = RestoreState.Restored(info)
                                    restorePassphrase = ""
                                    Toast.makeText(context, "Backup restored", Toast.LENGTH_SHORT).show()
                                } catch (e: Exception) {
                                    if (BuildConfig.DEBUG) Log.e("BackupRestore", "Restore failed", e)
                                    clearByteArray(verifiedState.data)
                                    restoreState = RestoreState.Error("Restore failed")
                                } finally {
                                    storage.clearPendingCipher(requestId)
                                    activeRequestIds.remove(requestId)
                                }
                            }
                        }
                    }
                ) {
                    Text("Restore", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmingRestore = null }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Composable
private fun RestoreFileInfo(
    fileName: String,
    passphrase: String,
    onPassphraseChange: (String) -> Unit
) {
    Spacer(modifier = Modifier.height(8.dp))
    Text(
        "File: $fileName",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Spacer(modifier = Modifier.height(8.dp))
    OutlinedTextField(
        value = passphrase,
        onValueChange = onPassphraseChange,
        label = { Text("Backup passphrase") },
        visualTransformation = PasswordVisualTransformation(),
        singleLine = true,
        modifier = Modifier.fillMaxWidth()
    )
}

@Composable
private fun RestoreProgressRow(label: String) {
    Spacer(modifier = Modifier.height(12.dp))
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center
    ) {
        CircularProgressIndicator(modifier = Modifier.size(24.dp))
        Spacer(modifier = Modifier.width(8.dp))
        Text(label)
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
