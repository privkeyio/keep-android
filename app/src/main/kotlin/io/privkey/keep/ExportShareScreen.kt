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
import javax.crypto.Cipher

private const val MAX_SINGLE_QR_BYTES = 600
private const val MAX_PASSPHRASE_LENGTH = 256
private const val MIN_PASSPHRASE_LENGTH = 8

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
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Text(
            text = message,
            modifier = Modifier.padding(16.dp),
            color = MaterialTheme.colorScheme.onErrorContainer
        )
    }
    Spacer(modifier = Modifier.height(16.dp))
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
    var passphrase by remember { mutableStateOf("") }
    var exportState by remember { mutableStateOf<ExportState>(ExportState.Idle) }
    var cipherError by remember { mutableStateOf<String?>(null) }
    val coroutineScope = rememberCoroutineScope()
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    DisposableEffect(lifecycleOwner) {
        setSecureScreen(context, true)
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_PAUSE, Lifecycle.Event.ON_STOP -> {
                    passphrase = ""
                    exportState = ExportState.Idle
                }
                else -> {}
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            passphrase = ""
            exportState = ExportState.Idle
            setSecureScreen(context, false)
            lifecycleOwner.lifecycle.removeObserver(observer)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
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
                if (state is ExportState.Error) {
                    ErrorCard(state.message)
                }
                cipherError?.let { ErrorCard(it) }

                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { if (it.length <= MAX_PASSPHRASE_LENGTH) passphrase = it },
                    label = { Text("Export Passphrase") },
                    placeholder = { Text("Enter a passphrase to encrypt") },
                    modifier = Modifier.fillMaxWidth(),
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true
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
                            cipherError = null
                            val cipher = onGetCipher()
                            if (cipher == null) {
                                cipherError = "No encryption key available"
                                return@Button
                            }
                            try {
                                onBiometricAuth(cipher) { authedCipher ->
                                    if (authedCipher != null) {
                                        storage.setPendingCipher(authedCipher)
                                        exportState = ExportState.Exporting
                                        coroutineScope.launch {
                                            try {
                                                val data = withContext(Dispatchers.IO) {
                                                    keepMobile.exportShare(passphrase)
                                                }
                                                val frames = generateFrames(data, MAX_SINGLE_QR_BYTES)
                                                exportState = ExportState.Success(data, frames)
                                            } catch (e: Exception) {
                                                Log.e("ExportShare", "Export failed: ${e::class.simpleName}")
                                                exportState = ExportState.Error("Export failed. Please try again.")
                                            } finally {
                                                storage.clearPendingCipher()
                                            }
                                        }
                                    } else {
                                        exportState = ExportState.Error("Authentication cancelled")
                                        Toast.makeText(context, "Authentication cancelled", Toast.LENGTH_SHORT).show()
                                    }
                                }
                            } catch (e: Exception) {
                                Log.e("ExportShare", "Failed to init cipher: ${e::class.simpleName}")
                                cipherError = "Failed to initialize encryption"
                            }
                        },
                        modifier = Modifier.weight(1f),
                        enabled = passphrase.length >= MIN_PASSPHRASE_LENGTH
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
                val showCopiedToast = {
                    Toast.makeText(context, "Share data copied", Toast.LENGTH_SHORT).show()
                }

                if (state.frames.size > 1) {
                    AnimatedQrCodeDisplay(
                        frames = state.frames,
                        label = "FROST Share Export",
                        fullData = state.data,
                        onCopied = showCopiedToast
                    )
                } else {
                    QrCodeDisplay(
                        data = state.data,
                        label = "FROST Share Export",
                        onCopied = showCopiedToast
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                OutlinedButton(
                    onClick = {
                        copySensitiveText(context, state.data)
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
        }
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
        val payloadBytes = (maxBytes - overhead) / 2
        val end = (offset + payloadBytes).coerceAtMost(dataBytes.size)
        chunks.add(dataBytes.copyOfRange(offset, end))
        offset = end
    }

    return chunks.mapIndexed { index, chunk ->
        val hex = chunk.joinToString("") { "%02x".format(it) }
        """{"f":$index,"t":${chunks.size},"d":"$hex"}"""
    }
}

