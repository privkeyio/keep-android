package io.privkey.keep

import android.util.Log
import android.widget.Toast
import io.privkey.keep.BuildConfig
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.ShareInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Arrays
import javax.crypto.Cipher

private const val MAX_SINGLE_QR_BYTES = 600
private const val MIN_PASSPHRASE_LENGTH = 15

sealed class ExportState {
    object Idle : ExportState()
    object Exporting : ExportState()
    data class Success(val data: String, val frames: List<String>) : ExportState()
    data class Error(val message: String) : ExportState()
}

@Composable
private fun ErrorCard(message: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
    ) {
        Text(
            text = message,
            modifier = Modifier.padding(16.dp),
            color = MaterialTheme.colorScheme.onErrorContainer
        )
    }
}

private enum class PassphraseStrength(val label: String) {
    WEAK("Weak"),
    FAIR("Fair"),
    GOOD("Good"),
    STRONG("Strong")
}

@Composable
private fun PassphraseStrength.color() = when (this) {
    PassphraseStrength.WEAK -> MaterialTheme.colorScheme.error
    PassphraseStrength.FAIR -> MaterialTheme.colorScheme.tertiary
    PassphraseStrength.GOOD, PassphraseStrength.STRONG -> MaterialTheme.colorScheme.primary
}

private fun calculatePassphraseStrength(passphrase: SecurePassphrase): PassphraseStrength {
    if (passphrase.length < MIN_PASSPHRASE_LENGTH) return PassphraseStrength.WEAK

    val hasLength12 = passphrase.length >= 12
    val hasLength16 = passphrase.length >= 16
    val hasMixedCase = passphrase.any { it.isUpperCase() } && passphrase.any { it.isLowerCase() }
    val hasDigits = passphrase.any { it.isDigit() }
    val hasSymbols = passphrase.any { !it.isLetterOrDigit() }

    val score = listOf(hasLength12, hasLength16, hasMixedCase, hasDigits, hasSymbols).count { it }

    return when {
        score >= 4 -> PassphraseStrength.STRONG
        score >= 3 -> PassphraseStrength.GOOD
        score >= 2 -> PassphraseStrength.FAIR
        else -> PassphraseStrength.WEAK
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

    DisposableEffect(lifecycleOwner) {
        setSecureScreen(context, true)

        fun clearSensitiveData() {
            passphrase.clear()
            confirmPassphrase.clear()
            passphraseDisplay = ""
            confirmPassphraseDisplay = ""
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
            text = "Export Share",
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
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)
                ) {
                    Text(
                        text = "Store this export securely. Anyone with this backup and passphrase can access your signing key share.",
                        modifier = Modifier.padding(16.dp),
                        color = MaterialTheme.colorScheme.onTertiaryContainer,
                        style = MaterialTheme.typography.bodySmall
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                if (state is ExportState.Error) {
                    ErrorCard(state.message)
                    Spacer(modifier = Modifier.height(16.dp))
                }

                cipherError?.let {
                    ErrorCard(it)
                    Spacer(modifier = Modifier.height(16.dp))
                }

                OutlinedTextField(
                    value = passphraseDisplay,
                    onValueChange = {
                        passphrase.update(it)
                        passphraseDisplay = it
                    },
                    label = { Text("Export Passphrase") },
                    placeholder = { Text("Enter a passphrase to encrypt") },
                    modifier = Modifier.fillMaxWidth(),
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true
                )

                if (passphrase.length > 0) {
                    Spacer(modifier = Modifier.height(8.dp))
                    val strength = calculatePassphraseStrength(passphrase)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        LinearProgressIndicator(
                            progress = (strength.ordinal + 1) / 4f,
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

                Spacer(modifier = Modifier.height(16.dp))

                OutlinedTextField(
                    value = confirmPassphraseDisplay,
                    onValueChange = {
                        confirmPassphrase.update(it)
                        confirmPassphraseDisplay = it
                    },
                    label = { Text("Confirm Passphrase") },
                    placeholder = { Text("Re-enter passphrase") },
                    modifier = Modifier.fillMaxWidth(),
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true,
                    isError = confirmPassphrase.length > 0 && passphrase.value != confirmPassphrase.value,
                    supportingText = if (confirmPassphrase.length > 0 && passphrase.value != confirmPassphrase.value) {
                        { Text("Passphrases do not match") }
                    } else null
                )

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "This passphrase encrypts the exported share. You will need it to import the share on another device.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Spacer(modifier = Modifier.height(24.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    OutlinedButton(
                        onClick = onDismiss,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Cancel")
                    }
                    Button(
                        onClick = {
                            if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
                                exportState = ExportState.Error("Passphrase must be at least $MIN_PASSPHRASE_LENGTH characters")
                                return@Button
                            }
                            if (passphrase.value != confirmPassphrase.value) {
                                exportState = ExportState.Error("Passphrases do not match")
                                return@Button
                            }
                            if (calculatePassphraseStrength(passphrase) == PassphraseStrength.WEAK) {
                                exportState = ExportState.Error("Passphrase is too weak. Add length, mixed case, numbers, or symbols.")
                                return@Button
                            }
                            cipherError = null
                            val cipher = onGetCipher()
                            if (cipher == null) {
                                cipherError = "No encryption key available"
                                return@Button
                            }
                            try {
                                val passphraseChars = passphrase.toCharArray()
                                onBiometricAuth(cipher) { authedCipher ->
                                    if (authedCipher != null) {
                                        val exportId = java.util.UUID.randomUUID().toString()
                                        storage.setPendingCipher(exportId, authedCipher)
                                        exportState = ExportState.Exporting
                                        coroutineScope.launch {
                                            try {
                                                val passphraseStr = String(passphraseChars)
                                                val data = withContext(Dispatchers.IO) {
                                                    storage.setRequestIdContext(exportId)
                                                    try {
                                                        keepMobile.exportShare(passphraseStr)
                                                    } finally {
                                                        storage.clearRequestIdContext()
                                                    }
                                                }
                                                val frames = generateFrames(data, MAX_SINGLE_QR_BYTES)
                                                exportState = ExportState.Success(data, frames)
                                            } catch (e: Exception) {
                                                if (BuildConfig.DEBUG) Log.e("ExportShare", "Export failed: ${e::class.simpleName}")
                                                exportState = ExportState.Error("Export failed. Please try again.")
                                            } finally {
                                                Arrays.fill(passphraseChars, '\u0000')
                                                storage.clearPendingCipher(exportId)
                                            }
                                        }
                                    } else {
                                        Arrays.fill(passphraseChars, '\u0000')
                                        exportState = ExportState.Error("Authentication cancelled")
                                        Toast.makeText(context, "Authentication cancelled", Toast.LENGTH_SHORT).show()
                                    }
                                }
                            } catch (e: Exception) {
                                if (BuildConfig.DEBUG) Log.e("ExportShare", "Failed to init cipher: ${e::class.simpleName}")
                                cipherError = "Failed to initialize encryption"
                            }
                        },
                        modifier = Modifier.weight(1f),
                        enabled = passphrase.length >= MIN_PASSPHRASE_LENGTH &&
                            passphrase.value == confirmPassphrase.value &&
                            calculatePassphraseStrength(passphrase) != PassphraseStrength.WEAK
                    ) {
                        Text("Export")
                    }
                }
            }

            is ExportState.Exporting -> {
                CircularProgressIndicator()
                Spacer(modifier = Modifier.height(16.dp))
                Text("Exporting share...")
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
    val showCopiedToast = { Toast.makeText(context, "Share data copied", Toast.LENGTH_SHORT).show() }
    val isAnimated = frames.size > 1

    if (isAnimated) {
        AnimatedQrCodeDisplay(
            frames = frames,
            label = "FROST Share Export",
            fullData = data,
            onCopied = showCopiedToast
        )
    } else {
        QrCodeDisplay(
            data = data,
            label = "FROST Share Export",
            onCopied = showCopiedToast
        )
    }

    Spacer(modifier = Modifier.height(24.dp))

    OutlinedButton(
        onClick = {
            copySensitiveText(context, data)
            showCopiedToast()
        },
        modifier = Modifier.fillMaxWidth()
    ) {
        Text("Copy to Clipboard")
    }

    Spacer(modifier = Modifier.height(8.dp))

    Button(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
        Text("Done")
    }
}

private fun generateFrames(data: String, maxBytes: Int): List<String> {
    val dataBytes = data.toByteArray(Charsets.UTF_8)
    if (dataBytes.size <= maxBytes) return listOf(data)

    fun jsonOverhead(frameIndex: Int, totalFrames: Int): Int {
        return """{"f":$frameIndex,"t":$totalFrames,"d":""}""".length
    }

    val chunks = mutableListOf<ByteArray>()
    var offset = 0
    while (offset < dataBytes.size) {
        val frameIndex = chunks.size
        val estimatedTotal = ((dataBytes.size - offset) / ((maxBytes - 30) / 2) + frameIndex + 1)
            .coerceAtLeast(frameIndex + 1)
        val overhead = jsonOverhead(frameIndex, estimatedTotal)
        val payloadBytes = ((maxBytes - overhead) / 2).coerceAtLeast(1)
        val end = (offset + payloadBytes).coerceAtMost(dataBytes.size)
        chunks.add(dataBytes.copyOfRange(offset, end))
        offset = end
    }

    return chunks.mapIndexed { index, chunk ->
        val hex = chunk.joinToString("") { "%02x".format(it) }
        """{"f":$index,"t":${chunks.size},"d":"$hex"}"""
    }
}
