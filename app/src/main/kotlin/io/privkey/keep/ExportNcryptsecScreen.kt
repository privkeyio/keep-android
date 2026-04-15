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

private const val MIN_PASSWORD_LENGTH = 15

private sealed class NcryptsecExportState {
    object Idle : NcryptsecExportState()
    object Encrypting : NcryptsecExportState()
    data class Error(val message: String) : NcryptsecExportState()

    class Success(ncryptsec: String) : NcryptsecExportState() {
        private var chars: CharArray? = ncryptsec.toCharArray()

        val ncryptsec: String @Synchronized get() = chars?.let { String(it) } ?: ""

        @Synchronized
        fun clear() {
            chars?.let { Arrays.fill(it, '\u0000') }
            chars = null
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportNcryptsecScreen(
    keepMobile: KeepMobile,
    shareInfo: ShareInfo,
    storage: AndroidKeystoreStorage,
    onGetCipher: () -> Cipher?,
    onBiometricAuth: (Cipher, (Cipher?) -> Unit) -> Unit,
    onDismiss: () -> Unit
) {
    val password = remember { SecurePassphrase() }
    val confirmPassword = remember { SecurePassphrase() }
    var passwordDisplay by remember { mutableStateOf("") }
    var confirmPasswordDisplay by remember { mutableStateOf("") }
    var exportState by remember { mutableStateOf<NcryptsecExportState>(NcryptsecExportState.Idle) }
    var cipherError by remember { mutableStateOf<String?>(null) }
    val coroutineScope = rememberCoroutineScope()
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var exportJob by remember { mutableStateOf<Job?>(null) }
    val sessionCanceled = remember { java.util.concurrent.atomic.AtomicBoolean(false) }
    val minLengthMessage = stringResource(R.string.export_ncryptsec_min_length, MIN_PASSWORD_LENGTH)
    val passwordsMismatchMessage = stringResource(R.string.export_ncryptsec_passwords_mismatch)
    val tooWeakMessage = stringResource(R.string.export_ncryptsec_too_weak)
    val biometricUnavailableMessage = stringResource(R.string.export_ncryptsec_biometric_unavailable)
    val noEncryptionKeyMessage = stringResource(R.string.export_ncryptsec_no_encryption_key)
    val exportFailedMessage = stringResource(R.string.export_ncryptsec_export_failed)
    val authCancelledMessage = stringResource(R.string.export_ncryptsec_auth_cancelled)
    val initFailedMessage = stringResource(R.string.export_ncryptsec_init_failed)

    DisposableEffect(lifecycleOwner) {
        setSecureScreen(context, true)

        fun clearSensitiveData() {
            sessionCanceled.set(true)
            exportJob?.cancel()
            exportJob = null
            password.clear()
            confirmPassword.clear()
            passwordDisplay = ""
            confirmPasswordDisplay = ""
            (exportState as? NcryptsecExportState.Success)?.clear()
            exportState = NcryptsecExportState.Idle
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
            text = stringResource(R.string.export_ncryptsec_title),
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
            is NcryptsecExportState.Idle, is NcryptsecExportState.Error -> {
                NcryptsecInputForm(
                    errorMessage = (state as? NcryptsecExportState.Error)?.message,
                    cipherError = cipherError,
                    password = password,
                    confirmPassword = confirmPassword,
                    passwordDisplay = passwordDisplay,
                    confirmPasswordDisplay = confirmPasswordDisplay,
                    onPasswordChange = {
                        password.update(it)
                        passwordDisplay = if (password.length == it.length) it else passwordDisplay
                    },
                    onConfirmPasswordChange = {
                        confirmPassword.update(it)
                        confirmPasswordDisplay = if (confirmPassword.length == it.length) it else confirmPasswordDisplay
                    },
                    onExport = {
                        if (password.length < MIN_PASSWORD_LENGTH) {
                            exportState = NcryptsecExportState.Error(minLengthMessage)
                            return@NcryptsecInputForm
                        }
                        if (!password.contentEquals(confirmPassword)) {
                            exportState = NcryptsecExportState.Error(passwordsMismatchMessage)
                            return@NcryptsecInputForm
                        }
                        if (calculatePasswordStrength(password) == PasswordStrength.WEAK) {
                            exportState = NcryptsecExportState.Error(tooWeakMessage)
                            return@NcryptsecInputForm
                        }
                        cipherError = null
                        val cipher = try {
                            onGetCipher()
                        } catch (e: BiometricHelper.BiometricNotReadyException) {
                            cipherError = e.message ?: biometricUnavailableMessage
                            return@NcryptsecInputForm
                        }
                        if (cipher == null) {
                            cipherError = noEncryptionKeyMessage
                            return@NcryptsecInputForm
                        }
                        val passwordChars = password.toCharArray()
                        fun clearChars() = Arrays.fill(passwordChars, '\u0000')
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
                                    exportState = NcryptsecExportState.Encrypting
                                    // NOTE: String(passwordChars) below materializes an unwipable
                                    // copy because the UniFFI surface requires String. Residual
                                    // risk: password bytes linger in the String's backing array
                                    // until GC. Same applies to the returned ncryptsec.
                                    exportJob = coroutineScope.launch {
                                        try {
                                            val ncryptsec = withContext(Dispatchers.IO) {
                                                storage.setRequestIdContext(exportId)
                                                try {
                                                    keepMobile.exportNcryptsec(String(passwordChars))
                                                } finally {
                                                    storage.clearRequestIdContext()
                                                }
                                            }
                                            password.clear()
                                            confirmPassword.clear()
                                            passwordDisplay = ""
                                            confirmPasswordDisplay = ""
                                            (exportState as? NcryptsecExportState.Success)?.clear()
                                            exportState = NcryptsecExportState.Success(ncryptsec)
                                        } catch (e: CancellationException) {
                                            throw e
                                        } catch (e: Exception) {
                                            if (BuildConfig.DEBUG) Log.e("ExportNcryptsec", "Export failed: ${e::class.simpleName}")
                                            exportState = NcryptsecExportState.Error(exportFailedMessage)
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
                                    exportState = NcryptsecExportState.Error(authCancelledMessage)
                                    Toast.makeText(context, authCancelledMessage, Toast.LENGTH_SHORT).show()
                                }
                            }
                        } catch (e: Exception) {
                            clearChars()
                            if (BuildConfig.DEBUG) Log.e("ExportNcryptsec", "Failed to init cipher: ${e::class.simpleName}")
                            cipherError = initFailedMessage
                        }
                    },
                    onCancel = {
                        password.clear()
                        confirmPassword.clear()
                        passwordDisplay = ""
                        confirmPasswordDisplay = ""
                        onDismiss()
                    }
                )
            }

            is NcryptsecExportState.Encrypting -> {
                CircularProgressIndicator()
                Spacer(modifier = Modifier.height(16.dp))
                Text(stringResource(R.string.export_ncryptsec_encrypting))
            }

            is NcryptsecExportState.Success -> {
                NcryptsecSuccessContent(
                    ncryptsec = state.ncryptsec,
                    onDismiss = onDismiss
                )
            }
        }
    }
}

private enum class PasswordStrength {
    WEAK,
    FAIR,
    GOOD,
    STRONG
}

@Composable
private fun PasswordStrength.label(): String = when (this) {
    PasswordStrength.WEAK -> stringResource(R.string.export_ncryptsec_strength_weak)
    PasswordStrength.FAIR -> stringResource(R.string.export_ncryptsec_strength_fair)
    PasswordStrength.GOOD -> stringResource(R.string.export_ncryptsec_strength_good)
    PasswordStrength.STRONG -> stringResource(R.string.export_ncryptsec_strength_strong)
}

@Composable
private fun PasswordStrength.color() = when (this) {
    PasswordStrength.WEAK -> MaterialTheme.colorScheme.error
    PasswordStrength.FAIR -> MaterialTheme.colorScheme.tertiary
    PasswordStrength.GOOD -> MaterialTheme.colorScheme.primary
    PasswordStrength.STRONG -> MaterialTheme.colorScheme.primary
}

private fun calculatePasswordStrength(password: SecurePassphrase): PasswordStrength {
    if (password.length < MIN_PASSWORD_LENGTH) return PasswordStrength.WEAK

    var score = 0
    if (password.length >= 16) score++
    if (password.length >= 20) score++
    if (password.any { it.isUpperCase() } && password.any { it.isLowerCase() }) score++
    if (password.any { it.isDigit() }) score++
    if (password.any { !it.isLetterOrDigit() }) score++

    return when {
        score >= 4 -> PasswordStrength.STRONG
        score >= 3 -> PasswordStrength.GOOD
        score >= 2 -> PasswordStrength.FAIR
        else -> PasswordStrength.WEAK
    }
}

@Composable
private fun PasswordStrengthIndicator(strength: PasswordStrength) {
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
private fun ErrorCard(message: String) {
    StatusCard(
        text = message,
        containerColor = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer
    )
}

@Composable
private fun NcryptsecInputForm(
    errorMessage: String?,
    cipherError: String?,
    password: SecurePassphrase,
    confirmPassword: SecurePassphrase,
    passwordDisplay: String,
    confirmPasswordDisplay: String,
    onPasswordChange: (String) -> Unit,
    onConfirmPasswordChange: (String) -> Unit,
    onExport: () -> Unit,
    onCancel: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)
    ) {
        Text(
            text = stringResource(R.string.export_ncryptsec_info),
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
        value = passwordDisplay,
        onValueChange = onPasswordChange,
        label = { Text(stringResource(R.string.export_ncryptsec_password_label)) },
        placeholder = { Text(stringResource(R.string.export_ncryptsec_password_placeholder)) },
        modifier = Modifier.fillMaxWidth(),
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        singleLine = true
    )

    if (password.length > 0) {
        Spacer(modifier = Modifier.height(8.dp))
        PasswordStrengthIndicator(calculatePasswordStrength(password))
    }

    Spacer(modifier = Modifier.height(16.dp))

    OutlinedTextField(
        value = confirmPasswordDisplay,
        onValueChange = onConfirmPasswordChange,
        label = { Text(stringResource(R.string.export_ncryptsec_confirm_label)) },
        placeholder = { Text(stringResource(R.string.export_ncryptsec_confirm_placeholder)) },
        modifier = Modifier.fillMaxWidth(),
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        singleLine = true,
        isError = confirmPassword.length > 0 && !password.contentEquals(confirmPassword),
        supportingText = if (confirmPassword.length > 0 && !password.contentEquals(confirmPassword)) {
            { Text(stringResource(R.string.export_ncryptsec_passwords_mismatch)) }
        } else null
    )

    Spacer(modifier = Modifier.height(16.dp))

    Text(
        text = stringResource(R.string.export_ncryptsec_footer),
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
            Text(stringResource(R.string.export_ncryptsec_cancel))
        }
        Button(
            onClick = onExport,
            modifier = Modifier.weight(1f),
            enabled = password.length >= MIN_PASSWORD_LENGTH &&
                password.contentEquals(confirmPassword) &&
                calculatePasswordStrength(password) != PasswordStrength.WEAK
        ) {
            Text(stringResource(R.string.export_ncryptsec_encrypt))
        }
    }
}

@Composable
private fun NcryptsecSuccessContent(
    ncryptsec: String,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val copiedMessage = stringResource(R.string.export_ncryptsec_copied_toast)
    val showCopiedToast = { Toast.makeText(context, copiedMessage, Toast.LENGTH_SHORT).show() }
    var showClipboardWarning by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
    ) {
        Text(
            text = stringResource(R.string.export_ncryptsec_danger),
            modifier = Modifier.padding(16.dp),
            color = MaterialTheme.colorScheme.onErrorContainer,
            style = MaterialTheme.typography.bodySmall
        )
    }

    Spacer(modifier = Modifier.height(16.dp))

    QrCodeDisplay(
        data = ncryptsec,
        label = stringResource(R.string.export_ncryptsec_qr_label),
        onTapToCopy = { showClipboardWarning = true },
        onCopied = showCopiedToast
    )

    Spacer(modifier = Modifier.height(24.dp))

    OutlinedButton(
        onClick = { showClipboardWarning = true },
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(stringResource(R.string.export_ncryptsec_copy_to_clipboard))
    }

    if (showClipboardWarning) {
        AlertDialog(
            onDismissRequest = { showClipboardWarning = false },
            title = { Text(stringResource(R.string.export_ncryptsec_clipboard_dialog_title)) },
            text = { Text(stringResource(R.string.export_ncryptsec_clipboard_dialog_text)) },
            confirmButton = {
                TextButton(onClick = {
                    showClipboardWarning = false
                    copySensitiveText(context, ncryptsec)
                    showCopiedToast()
                }) {
                    Text(stringResource(R.string.export_ncryptsec_copy_anyway))
                }
            },
            dismissButton = {
                TextButton(onClick = { showClipboardWarning = false }) {
                    Text(stringResource(R.string.export_ncryptsec_cancel))
                }
            }
        )
    }

    Spacer(modifier = Modifier.height(8.dp))

    Button(
        onClick = onDismiss,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(stringResource(R.string.export_ncryptsec_done))
    }
}
