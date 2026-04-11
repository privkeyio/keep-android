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
import kotlinx.coroutines.currentCoroutineContext
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

    DisposableEffect(lifecycleOwner) {
        setSecureScreen(context, true)

        fun clearSensitiveData() {
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
            text = "Export Encrypted Key",
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
                        passwordDisplay = it
                    },
                    onConfirmPasswordChange = {
                        confirmPassword.update(it)
                        confirmPasswordDisplay = it
                    },
                    onExport = {
                        if (password.length < MIN_PASSWORD_LENGTH) {
                            exportState = NcryptsecExportState.Error("Password must be at least $MIN_PASSWORD_LENGTH characters")
                            return@NcryptsecInputForm
                        }
                        if (!password.contentEquals(confirmPassword)) {
                            exportState = NcryptsecExportState.Error("Passwords do not match")
                            return@NcryptsecInputForm
                        }
                        if (calculatePasswordStrength(password) == PasswordStrength.WEAK) {
                            exportState = NcryptsecExportState.Error("Password is too weak. Add length, mixed case, numbers, or symbols.")
                            return@NcryptsecInputForm
                        }
                        cipherError = null
                        val cipher = try {
                            onGetCipher()
                        } catch (e: BiometricHelper.BiometricNotReadyException) {
                            cipherError = e.message ?: "Biometric authentication is unavailable"
                            return@NcryptsecInputForm
                        }
                        if (cipher == null) {
                            cipherError = "No encryption key available"
                            return@NcryptsecInputForm
                        }
                        val passwordChars = password.toCharArray()
                        fun clearChars() = Arrays.fill(passwordChars, '\u0000')
                        try {
                            onBiometricAuth(cipher) { authedCipher ->
                                if (authedCipher != null) {
                                    val exportId = java.util.UUID.randomUUID().toString()
                                    storage.setPendingCipher(exportId, authedCipher)
                                    exportState = NcryptsecExportState.Encrypting
                                    coroutineScope.launch {
                                        currentCoroutineContext()[Job]?.invokeOnCompletion { cause ->
                                            if (cause is CancellationException) {
                                                clearChars()
                                                storage.clearPendingCipher(exportId)
                                            }
                                        }
                                        try {
                                            val ncryptsec = withContext(Dispatchers.IO) {
                                                storage.setRequestIdContext(exportId)
                                                try {
                                                    keepMobile.exportNcryptsec(String(passwordChars))
                                                } finally {
                                                    storage.clearRequestIdContext()
                                                }
                                            }
                                            (exportState as? NcryptsecExportState.Success)?.clear()
                                            exportState = NcryptsecExportState.Success(ncryptsec)
                                        } catch (e: Exception) {
                                            if (BuildConfig.DEBUG) Log.e("ExportNcryptsec", "Export failed: ${e::class.simpleName}")
                                            exportState = NcryptsecExportState.Error("Export failed. Please try again.")
                                        } finally {
                                            clearChars()
                                            storage.clearPendingCipher(exportId)
                                        }
                                    }
                                } else {
                                    clearChars()
                                    exportState = NcryptsecExportState.Error("Authentication cancelled")
                                    Toast.makeText(context, "Authentication cancelled", Toast.LENGTH_SHORT).show()
                                }
                            }
                        } catch (e: Exception) {
                            clearChars()
                            if (BuildConfig.DEBUG) Log.e("ExportNcryptsec", "Failed to init cipher: ${e::class.simpleName}")
                            cipherError = "Failed to initialize encryption"
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
                Text("Encrypting key...")
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

private enum class PasswordStrength(val label: String) {
    WEAK("Weak"),
    FAIR("Fair"),
    GOOD("Good"),
    STRONG("Strong")
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
            text = strength.label,
            style = MaterialTheme.typography.labelSmall,
            color = strength.color()
        )
    }
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
            text = "This encrypts your private key using NIP-49 (ncryptsec). The result can be imported into any Nostr client that supports NIP-49.",
            modifier = Modifier.padding(16.dp),
            color = MaterialTheme.colorScheme.onTertiaryContainer,
            style = MaterialTheme.typography.bodySmall
        )
    }

    Spacer(modifier = Modifier.height(16.dp))

    errorMessage?.let {
        StatusCard(
            text = it,
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer
        )
        Spacer(modifier = Modifier.height(16.dp))
    }

    cipherError?.let {
        StatusCard(
            text = it,
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer
        )
        Spacer(modifier = Modifier.height(16.dp))
    }

    OutlinedTextField(
        value = passwordDisplay,
        onValueChange = onPasswordChange,
        label = { Text("Encryption Password") },
        placeholder = { Text("Enter a password to encrypt") },
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
        label = { Text("Confirm Password") },
        placeholder = { Text("Re-enter password") },
        modifier = Modifier.fillMaxWidth(),
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        singleLine = true,
        isError = confirmPassword.length > 0 && !password.contentEquals(confirmPassword),
        supportingText = if (confirmPassword.length > 0 && !password.contentEquals(confirmPassword)) {
            { Text("Passwords do not match") }
        } else null
    )

    Spacer(modifier = Modifier.height(16.dp))

    Text(
        text = "This password encrypts your private key. You will need it to decrypt in another Nostr client.",
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
            Text("Cancel")
        }
        Button(
            onClick = onExport,
            modifier = Modifier.weight(1f),
            enabled = password.length >= MIN_PASSWORD_LENGTH &&
                password.contentEquals(confirmPassword) &&
                calculatePasswordStrength(password) != PasswordStrength.WEAK
        ) {
            Text("Encrypt")
        }
    }
}

@Composable
private fun NcryptsecSuccessContent(
    ncryptsec: String,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val showCopiedToast = { Toast.makeText(context, "ncryptsec copied", Toast.LENGTH_SHORT).show() }
    var showClipboardWarning by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
    ) {
        Text(
            text = "Anyone with this string and the password can access your private key. Do not share it publicly.",
            modifier = Modifier.padding(16.dp),
            color = MaterialTheme.colorScheme.onErrorContainer,
            style = MaterialTheme.typography.bodySmall
        )
    }

    Spacer(modifier = Modifier.height(16.dp))

    QrCodeDisplay(
        data = ncryptsec,
        label = "NIP-49 Encrypted Key",
        onTapToCopy = { showClipboardWarning = true },
        onCopied = showCopiedToast
    )

    Spacer(modifier = Modifier.height(24.dp))

    OutlinedButton(
        onClick = { showClipboardWarning = true },
        modifier = Modifier.fillMaxWidth()
    ) {
        Text("Copy to Clipboard")
    }

    if (showClipboardWarning) {
        AlertDialog(
            onDismissRequest = { showClipboardWarning = false },
            title = { Text("Copy to clipboard?") },
            text = { Text("Other apps on your device may be able to read clipboard contents. The QR code export is more secure.") },
            confirmButton = {
                TextButton(onClick = {
                    showClipboardWarning = false
                    copySensitiveText(context, ncryptsec)
                    showCopiedToast()
                }) {
                    Text("Copy anyway")
                }
            },
            dismissButton = {
                TextButton(onClick = { showClipboardWarning = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    Spacer(modifier = Modifier.height(8.dp))

    Button(
        onClick = onDismiss,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text("Done")
    }
}
