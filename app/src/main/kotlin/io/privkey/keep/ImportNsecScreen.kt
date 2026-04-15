package io.privkey.keep

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.Log
import io.privkey.keep.uniffi.isValidNsecFormat
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import javax.crypto.Cipher

private const val MAX_NSEC_LENGTH = 128

@Composable
fun ImportNsecScreen(
    onImport: (nsec: String, name: String, cipher: Cipher) -> Unit,
    onGetCipher: () -> Cipher,
    onBiometricAuth: (Cipher, (Cipher?) -> Unit) -> Unit,
    onDismiss: () -> Unit,
    importState: ImportState
) {
    val context = LocalContext.current
    val nsecData = remember { SecureShareData(MAX_NSEC_LENGTH) }
    var nsecDisplay by remember { mutableStateOf("") }
    val defaultKeyName = stringResource(R.string.create_account_default_key_name)
    var keyName by remember { mutableStateOf(defaultKeyName) }
    var showScanner by remember { mutableStateOf(false) }
    var scanError by remember { mutableStateOf<String?>(null) }
    var isNsecVisible by remember { mutableStateOf(false) }

    val isInputEnabled = importState is ImportState.Idle || importState is ImportState.Error
    val scanTooLongMsg = stringResource(R.string.import_nsec_scan_too_long)
    val biometricInvalidatedMsg = stringResource(R.string.import_nsec_biometric_invalidated)
    val biometricUnavailableMsg = stringResource(R.string.import_nsec_biometric_unavailable)
    val cipherFailedMsg = stringResource(R.string.import_nsec_cipher_failed)

    DisposableEffect(context) {
        setSecureScreen(context, true)
        onDispose { setSecureScreen(context, false) }
    }

    LaunchedEffect(importState) {
        if (importState is ImportState.Success) {
            nsecData.clear()
            nsecDisplay = ""
        }
    }

    DisposableEffect(Unit) {
        onDispose {
            nsecData.clear()
            nsecDisplay = ""
        }
    }

    if (showScanner) {
        QrScannerScreen(
            onCodeScanned = { code ->
                showScanner = false
                if (code.length > MAX_NSEC_LENGTH) {
                    scanError = scanTooLongMsg
                } else {
                    scanError = null
                    nsecData.update(code)
                    nsecDisplay = code
                }
            },
            onDismiss = {
                showScanner = false
            },
            validator = ::isValidNsecFormat,
            title = stringResource(R.string.import_nsec_scan_title)
        )
        return
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
            text = stringResource(R.string.import_nsec_title),
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(24.dp))

        OutlinedTextField(
            value = nsecDisplay,
            onValueChange = {
                if (it.length <= MAX_NSEC_LENGTH) {
                    scanError = null
                    nsecData.update(it)
                    nsecDisplay = it
                }
            },
            label = { Text(stringResource(R.string.import_nsec_label)) },
            placeholder = { Text(stringResource(R.string.import_nsec_placeholder)) },
            modifier = Modifier.fillMaxWidth(),
            minLines = 2,
            maxLines = 3,
            enabled = isInputEnabled,
            visualTransformation = if (isNsecVisible) VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = {
                IconButton(
                    onClick = { isNsecVisible = !isNsecVisible },
                    enabled = isInputEnabled
                ) {
                    Icon(
                        if (isNsecVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                        contentDescription = if (isNsecVisible) stringResource(R.string.import_nsec_hide) else stringResource(R.string.import_nsec_show)
                    )
                }
            }
        )

        Spacer(modifier = Modifier.height(8.dp))

        OutlinedButton(
            onClick = { showScanner = true },
            modifier = Modifier.fillMaxWidth(),
            enabled = isInputEnabled
        ) {
            Text(stringResource(R.string.import_nsec_scan_qr))
        }

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = keyName,
            onValueChange = { if (it.length <= 64) keyName = it },
            label = { Text(stringResource(R.string.import_nsec_key_name_label)) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            enabled = isInputEnabled
        )

        Spacer(modifier = Modifier.height(24.dp))

        val currentScanError = scanError
        if (currentScanError != null) {
            StatusCard(
                text = currentScanError,
                containerColor = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer
            )
            Spacer(modifier = Modifier.height(16.dp))
        }

        if (importState is ImportState.Error) {
            StatusCard(
                text = importState.message,
                containerColor = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer
            )
            Spacer(modifier = Modifier.height(16.dp))
        }

        if (importState is ImportState.Success) {
            StatusCard(
                text = stringResource(R.string.import_nsec_imported, importState.name),
                containerColor = MaterialTheme.colorScheme.primaryContainer,
                contentColor = MaterialTheme.colorScheme.onPrimaryContainer
            )
            Spacer(modifier = Modifier.height(16.dp))
        }

        if (importState is ImportState.Importing) {
            CircularProgressIndicator()
        } else {
            ImportButtons(
                importState = importState,
                canImport = nsecData.isNotBlank() && isInputEnabled,
                onDismiss = onDismiss,
                onImportClick = { onError ->
                    try {
                        val cipher = onGetCipher()
                        onBiometricAuth(cipher) { authedCipher ->
                            if (authedCipher != null) {
                                onImport(nsecData.valueUnsafe(), keyName, authedCipher)
                            }
                        }
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        if (BuildConfig.DEBUG) Log.e("ImportNsec", "Biometric key invalidated: ${e::class.simpleName}")
                        onError(biometricInvalidatedMsg)
                    } catch (e: BiometricHelper.BiometricNotReadyException) {
                        onError(e.message ?: biometricUnavailableMsg)
                    } catch (e: Exception) {
                        if (BuildConfig.DEBUG) Log.e("ImportNsec", "Failed to initialize cipher: ${e::class.simpleName}: ${e.message}", e)
                        onError(cipherFailedMsg)
                    }
                }
            )
        }
    }
}
