package io.privkey.keep

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.Log
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import javax.crypto.Cipher

private const val MAX_NSEC_LENGTH = 128

@OptIn(ExperimentalMaterial3Api::class)
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
    var keyName by remember { mutableStateOf("Mobile Key") }
    var showScanner by remember { mutableStateOf(false) }

    val isInputEnabled = importState is ImportState.Idle || importState is ImportState.Error

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
                nsecData.update(code)
                nsecDisplay = code
                showScanner = false
            },
            onDismiss = { showScanner = false },
            validator = ::isValidNsecFormat,
            title = "Scan nsec QR Code"
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
            text = "Import nsec",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(24.dp))

        OutlinedTextField(
            value = nsecDisplay,
            onValueChange = {
                if (it.length <= MAX_NSEC_LENGTH) {
                    nsecData.update(it)
                    nsecDisplay = it
                }
            },
            label = { Text("nsec") },
            placeholder = { Text("nsec1...") },
            modifier = Modifier.fillMaxWidth(),
            minLines = 2,
            maxLines = 3,
            enabled = isInputEnabled
        )

        Spacer(modifier = Modifier.height(8.dp))

        OutlinedButton(
            onClick = { showScanner = true },
            modifier = Modifier.fillMaxWidth(),
            enabled = isInputEnabled
        ) {
            Text("Scan QR Code")
        }

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = keyName,
            onValueChange = { if (it.length <= 64) keyName = it },
            label = { Text("Key Name") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            enabled = isInputEnabled
        )

        Spacer(modifier = Modifier.height(24.dp))

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
                text = "Key '${importState.name}' imported successfully",
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
                        onError("Biometric key invalidated. Please re-enroll biometrics.")
                    } catch (e: Exception) {
                        if (BuildConfig.DEBUG) Log.e("ImportNsec", "Failed to initialize cipher: ${e::class.simpleName}")
                        onError("Failed to initialize encryption")
                    }
                }
            )
        }
    }
}
