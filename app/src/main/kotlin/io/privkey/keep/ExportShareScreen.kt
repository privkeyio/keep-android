package io.privkey.keep

import android.util.Log
import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import io.privkey.keep.nip55.AUDIT_OP_EXPORT_SHARE
import io.privkey.keep.nip55.auditKeyExport
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.ShareInfo
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Arrays
import javax.crypto.Cipher

private const val MAX_SINGLE_QR_BYTES = 600
private const val MIN_PASSPHRASE_LENGTH = 15

sealed class ExportState {
    object Idle : ExportState()
    object Exporting : ExportState()
    data class Error(val message: String) : ExportState()

    class Success(data: String, frames: List<String>) : ExportState() {
        private var dataChars: CharArray? = data.toCharArray()
        private var frameChars: List<CharArray>? = frames.map { it.toCharArray() }

        val data: String @Synchronized get() = dataChars?.let { String(it) } ?: ""
        val frames: List<String> @Synchronized get() = frameChars?.map { String(it) } ?: emptyList()

        @Synchronized
        fun clear() {
            dataChars?.let { Arrays.fill(it, '\u0000') }
            dataChars = null
            frameChars?.forEach { Arrays.fill(it, '\u0000') }
            frameChars = null
        }
    }
}

@Composable
private fun ErrorCard(message: String) {
    StatusCard(
        text = message,
        containerColor = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer
    )
}

private enum class PassphraseStrength {
    WEAK,
    FAIR,
    GOOD,
    STRONG
}

@Composable
private fun PassphraseStrength.label(): String = when (this) {
    PassphraseStrength.WEAK -> stringResource(R.string.export_share_strength_weak)
    PassphraseStrength.FAIR -> stringResource(R.string.export_share_strength_fair)
    PassphraseStrength.GOOD -> stringResource(R.string.export_share_strength_good)
    PassphraseStrength.STRONG -> stringResource(R.string.export_share_strength_strong)
}

@Composable
private fun PassphraseStrength.color() = when (this) {
    PassphraseStrength.WEAK -> MaterialTheme.colorScheme.error
    PassphraseStrength.FAIR -> MaterialTheme.colorScheme.tertiary
    PassphraseStrength.GOOD -> MaterialTheme.colorScheme.primary
    PassphraseStrength.STRONG -> MaterialTheme.colorScheme.primary
}

private fun calculatePassphraseStrength(passphrase: SecurePassphrase): PassphraseStrength {
    if (passphrase.length < MIN_PASSPHRASE_LENGTH) return PassphraseStrength.WEAK

    var score = 0
    if (passphrase.length >= 12) score++
    if (passphrase.length >= 16) score++
    if (passphrase.any { it.isUpperCase() } && passphrase.any { it.isLowerCase() }) score++
    if (passphrase.any { it.isDigit() }) score++
    if (passphrase.any { !it.isLetterOrDigit() }) score++

    return when {
        score >= 4 -> PassphraseStrength.STRONG
        score >= 3 -> PassphraseStrength.GOOD
        score >= 2 -> PassphraseStrength.FAIR
        else -> PassphraseStrength.WEAK
    }
}

@Composable
private fun PassphraseStrengthIndicator(strength: PassphraseStrength) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        LinearProgressIndicator(
            progress = { (strength.ordinal + 1) / 4f },
            modifier = Modifier.weight(1f).height(4.dp),
            color = strength.color(),
            trackColor = MaterialTheme.colorScheme.surfaceVariant
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = strength.label(),
            style = MaterialTheme.typography.labelSmall,
            color = strength.color()
        )
    }
}

@Composable
private fun ExportInputForm(
    errorMessage: String?,
    cipherError: String?,
    passphrase: SecurePassphrase,
    confirmPassphrase: SecurePassphrase,
    passphraseDisplay: String,
    confirmPassphraseDisplay: String,
    onPassphraseChange: (String) -> Unit,
    onConfirmPassphraseChange: (String) -> Unit,
    onExport: () -> Unit,
    onCancel: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)
    ) {
        Text(
            text = stringResource(R.string.export_share_info),
            modifier = Modifier.padding(16.dp),
            color = MaterialTheme.colorScheme.onTertiaryContainer,
            style = MaterialTheme.typography.bodySmall
        )
    }

    Spacer(modifier = Modifier.height(16.dp))

    errorMessage?.let {
        ErrorCard(it)
        Spacer(modifier = Modifier.height(16.dp))
    }

    cipherError?.let {
        ErrorCard(it)
        Spacer(modifier = Modifier.height(16.dp))
    }

    OutlinedTextField(
        value = passphraseDisplay,
        onValueChange = onPassphraseChange,
        label = { Text(stringResource(R.string.export_share_passphrase_label)) },
        placeholder = { Text(stringResource(R.string.export_share_passphrase_placeholder)) },
        modifier = Modifier.fillMaxWidth(),
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        singleLine = true
    )

    if (passphrase.length > 0) {
        Spacer(modifier = Modifier.height(8.dp))
        PassphraseStrengthIndicator(calculatePassphraseStrength(passphrase))
    }

    Spacer(modifier = Modifier.height(16.dp))

    OutlinedTextField(
        value = confirmPassphraseDisplay,
        onValueChange = onConfirmPassphraseChange,
        label = { Text(stringResource(R.string.export_share_confirm_label)) },
        placeholder = { Text(stringResource(R.string.export_share_confirm_placeholder)) },
        modifier = Modifier.fillMaxWidth(),
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        singleLine = true,
        isError = confirmPassphrase.length > 0 && !passphrase.contentEquals(confirmPassphrase),
        supportingText = if (confirmPassphrase.length > 0 && !passphrase.contentEquals(confirmPassphrase)) {
            { Text(stringResource(R.string.export_share_passphrases_mismatch)) }
        } else null
    )

    Spacer(modifier = Modifier.height(16.dp))

    Text(
        text = stringResource(R.string.export_share_footer),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )

    Spacer(modifier = Modifier.height(24.dp))

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        OutlinedButton(
            onClick = onCancel,
            modifier = Modifier.weight(1f)
        ) {
            Text(stringResource(R.string.export_share_cancel))
        }
        Button(
            onClick = onExport,
            modifier = Modifier.weight(1f),
            enabled = passphrase.length >= MIN_PASSPHRASE_LENGTH &&
                passphrase.contentEquals(confirmPassphrase) &&
                calculatePassphraseStrength(passphrase) != PassphraseStrength.WEAK
        ) {
            Text(stringResource(R.string.export_share_export))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportShareScreen(
    keepMobile: KeepMobile,
    shareInfo: ShareInfo,
    storage: AndroidKeystoreStorage,
    onGetCipher: () -> Cipher?,
    onBiometricAuth: (Cipher, (Cipher?) -> Unit) -> Unit,
    onDismiss: () -> Unit
) {
    val passphrase = remember { SecurePassphrase() }
    val confirmPassphrase = remember { SecurePassphrase() }
    var passphraseDisplay by remember { mutableStateOf("") }
    var confirmPassphraseDisplay by remember { mutableStateOf("") }
    var exportState by remember { mutableStateOf<ExportState>(ExportState.Idle) }
    var cipherError by remember { mutableStateOf<String?>(null) }
    val coroutineScope = rememberCoroutineScope()
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var exportJob by remember { mutableStateOf<Job?>(null) }
    val sessionCanceled = remember { java.util.concurrent.atomic.AtomicBoolean(false) }
    val minLengthMessage = stringResource(R.string.export_share_min_length, MIN_PASSPHRASE_LENGTH)
    val passphrasesMismatchMessage = stringResource(R.string.export_share_passphrases_mismatch)
    val tooWeakMessage = stringResource(R.string.export_share_too_weak)
    val biometricUnavailableMessage = stringResource(R.string.export_share_biometric_unavailable)
    val noEncryptionKeyMessage = stringResource(R.string.export_share_no_encryption_key)
    val tooLargeMessage = stringResource(R.string.export_share_too_large)
    val exportFailedMessage = stringResource(R.string.export_share_export_failed)
    val authCancelledMessage = stringResource(R.string.export_share_auth_cancelled)
    val initFailedMessage = stringResource(R.string.export_share_init_failed)

    DisposableEffect(lifecycleOwner) {
        setSecureScreen(context, true)

        fun clearSensitiveData() {
            sessionCanceled.set(true)
            exportJob?.cancel()
            exportJob = null
            passphrase.clear()
            confirmPassphrase.clear()
            passphraseDisplay = ""
            confirmPassphraseDisplay = ""
            (exportState as? ExportState.Success)?.clear()
            exportState = ExportState.Idle
        }

        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_PAUSE || event == Lifecycle.Event.ON_STOP) {
                clearSensitiveData()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            clearSensitiveData()
            setSecureScreen(context, false)
            lifecycleOwner.lifecycle.removeObserver(observer)
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
            text = stringResource(R.string.export_share_title),
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = shareInfo.name,
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(24.dp))

        when (val state = exportState) {
            is ExportState.Idle, is ExportState.Error -> {
                ExportInputForm(
                    errorMessage = (state as? ExportState.Error)?.message,
                    cipherError = cipherError,
                    passphrase = passphrase,
                    confirmPassphrase = confirmPassphrase,
                    passphraseDisplay = passphraseDisplay,
                    confirmPassphraseDisplay = confirmPassphraseDisplay,
                    onPassphraseChange = {
                        passphrase.update(it)
                        passphraseDisplay = it
                    },
                    onConfirmPassphraseChange = {
                        confirmPassphrase.update(it)
                        confirmPassphraseDisplay = it
                    },
                    onExport = {
                        if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
                            exportState = ExportState.Error(minLengthMessage)
                            return@ExportInputForm
                        }
                        if (!passphrase.contentEquals(confirmPassphrase)) {
                            exportState = ExportState.Error(passphrasesMismatchMessage)
                            return@ExportInputForm
                        }
                        if (calculatePassphraseStrength(passphrase) == PassphraseStrength.WEAK) {
                            exportState = ExportState.Error(tooWeakMessage)
                            return@ExportInputForm
                        }
                        cipherError = null
                        val cipher = try {
                            onGetCipher()
                        } catch (e: BiometricHelper.BiometricNotReadyException) {
                            cipherError = e.message ?: biometricUnavailableMessage
                            return@ExportInputForm
                        }
                        if (cipher == null) {
                            cipherError = noEncryptionKeyMessage
                            return@ExportInputForm
                        }
                        val passphraseChars = passphrase.toCharArray()
                        fun clearChars() = Arrays.fill(passphraseChars, '\u0000')
                        sessionCanceled.set(false)
                        try {
                            onBiometricAuth(cipher) { authedCipher ->
                                if (sessionCanceled.get()) {
                                    clearChars()
                                    return@onBiometricAuth
                                }
                                if (authedCipher != null) {
                                    val exportId = java.util.UUID.randomUUID().toString()
                                    storage.setPendingCipher(exportId, authedCipher)
                                    exportState = ExportState.Exporting
                                    exportJob = coroutineScope.launch {
                                        try {
                                            val data = withContext(Dispatchers.IO) {
                                                storage.setRequestIdContext(exportId)
                                                try {
                                                    keepMobile.exportShare(String(passphraseChars))
                                                } finally {
                                                    storage.clearRequestIdContext()
                                                }
                                            }
                                            // Audit the share export (best-effort; must never
                                            // fail the export itself).
                                            auditKeyExport(context, AUDIT_OP_EXPORT_SHARE)
                                            passphrase.clear()
                                            confirmPassphrase.clear()
                                            passphraseDisplay = ""
                                            confirmPassphraseDisplay = ""
                                            (exportState as? ExportState.Success)?.clear()
                                            val frames = try {
                                                withContext(Dispatchers.Default) {
                                                    io.privkey.keep.uniffi.generateAnimatedFrames(data, MAX_SINGLE_QR_BYTES.toUInt())
                                                }
                                            } catch (e: Exception) {
                                                if (BuildConfig.DEBUG) Log.w("ExportShare", "Frame generation failed: ${e::class.simpleName}")
                                                if (data.length > MAX_SINGLE_QR_BYTES) {
                                                    exportState = ExportState.Error(tooLargeMessage)
                                                    return@launch
                                                }
                                                listOf(data)
                                            }
                                            exportState = ExportState.Success(data, frames)
                                        } catch (e: CancellationException) {
                                            throw e
                                        } catch (e: Exception) {
                                            if (BuildConfig.DEBUG) Log.e("ExportShare", "Export failed: ${e::class.simpleName}")
                                            exportState = ExportState.Error(exportFailedMessage)
                                        }
                                    }.also { job ->
                                        job.invokeOnCompletion {
                                            clearChars()
                                            storage.clearPendingCipher(exportId)
                                            if (exportJob === job) exportJob = null
                                        }
                                    }
                                } else {
                                    clearChars()
                                    exportState = ExportState.Error(authCancelledMessage)
                                    Toast.makeText(context, authCancelledMessage, Toast.LENGTH_SHORT).show()
                                }
                            }
                        } catch (e: Exception) {
                            clearChars()
                            if (BuildConfig.DEBUG) Log.e("ExportShare", "Failed to init cipher: ${e::class.simpleName}")
                            cipherError = initFailedMessage
                        }
                    },
                    onCancel = {
                        passphrase.clear()
                        confirmPassphrase.clear()
                        passphraseDisplay = ""
                        confirmPassphraseDisplay = ""
                        onDismiss()
                    }
                )
            }

            is ExportState.Exporting -> {
                CircularProgressIndicator()
                Spacer(modifier = Modifier.height(16.dp))
                Text(stringResource(R.string.export_share_exporting))
            }

            is ExportState.Success -> {
                ExportSuccessContent(
                    data = state.data,
                    frames = state.frames,
                    onDismiss = onDismiss
                )
            }
        }
    }
}

@Composable
private fun ExportSuccessContent(
    data: String,
    frames: List<String>,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val copiedMessage = stringResource(R.string.export_share_copied_toast)
    val qrLabel = stringResource(R.string.export_share_qr_label)
    val showCopiedToast = { Toast.makeText(context, copiedMessage, Toast.LENGTH_SHORT).show() }
    val isAnimated = frames.size > 1
    var showClipboardWarning by remember { mutableStateOf(false) }

    if (isAnimated) {
        AnimatedQrCodeDisplay(
            frames = frames,
            label = qrLabel,
            fullData = data,
            onCopied = showCopiedToast
        )
    } else {
        QrCodeDisplay(
            data = data,
            label = qrLabel,
            onCopied = showCopiedToast
        )
    }

    Spacer(modifier = Modifier.height(24.dp))

    OutlinedButton(
        onClick = { showClipboardWarning = true },
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(stringResource(R.string.export_share_copy_to_clipboard))
    }

    if (showClipboardWarning) {
        AlertDialog(
            onDismissRequest = { showClipboardWarning = false },
            title = { Text(stringResource(R.string.export_share_clipboard_dialog_title)) },
            text = { Text(stringResource(R.string.export_share_clipboard_dialog_text)) },
            confirmButton = {
                TextButton(onClick = {
                    showClipboardWarning = false
                    copySensitiveText(context, data)
                    showCopiedToast()
                }) {
                    Text(stringResource(R.string.export_share_copy_anyway))
                }
            },
            dismissButton = {
                TextButton(onClick = { showClipboardWarning = false }) {
                    Text(stringResource(R.string.export_share_cancel))
                }
            }
        )
    }

    Spacer(modifier = Modifier.height(8.dp))

    Button(
        onClick = onDismiss,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(stringResource(R.string.export_share_done))
    }
}

