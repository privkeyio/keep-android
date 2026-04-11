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
import io.privkey.keep.uniffi.KeepMobile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.crypto.Cipher

private enum class CreateAccountStep { SETUP, SEED_WORDS, CONFIRM }

private const val MAX_MNEMONIC_LENGTH = 1024

@Composable
fun CreateAccountScreen(
    keepMobile: KeepMobile,
    onCreateAccount: (mnemonic: String, passphrase: String, name: String, cipher: Cipher) -> Unit,
    onGetCipher: () -> Cipher,
    onBiometricAuth: (Cipher, (Cipher?) -> Unit) -> Unit,
    onDismiss: () -> Unit,
    importState: ImportState
) {
    var step by remember { mutableStateOf(CreateAccountStep.SETUP) }
    val mnemonicData = remember { SecureShareData(MAX_MNEMONIC_LENGTH) }
    var keyName by remember { mutableStateOf("Mobile Key") }
    var isGenerating by remember { mutableStateOf(true) }

    val isInputEnabled = importState is ImportState.Idle || importState is ImportState.Error

    var generateError by remember { mutableStateOf<String?>(null) }
    var generateTrigger by remember { mutableIntStateOf(0) }

    LaunchedEffect(generateTrigger) {
        isGenerating = true
        generateError = null
        try {
            val mnemonic = withContext(Dispatchers.IO) { keepMobile.generateMnemonic(12u) }
            mnemonicData.update(mnemonic)
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.e("CreateAccount", "Failed to generate mnemonic: ${e::class.simpleName}")
            generateError = "Failed to generate seed words. Please try again."
        } finally {
            isGenerating = false
        }
    }

    LaunchedEffect(importState) {
        if (importState is ImportState.Success) {
            mnemonicData.clear()
        }
    }

    DisposableEffect(Unit) {
        onDispose {
            mnemonicData.clear()
        }
    }

    when (step) {
        CreateAccountStep.SETUP -> SetupStep(
            isGenerating = isGenerating,
            generateError = generateError,
            keyName = keyName,
            onKeyNameChange = { if (it.length <= 64) keyName = it },
            isInputEnabled = isInputEnabled,
            onNext = { step = CreateAccountStep.SEED_WORDS },
            onRetry = { generateTrigger++ },
            onDismiss = onDismiss
        )
        CreateAccountStep.SEED_WORDS -> SeedWordsStep(
            mnemonicData = mnemonicData,
            onNext = { step = CreateAccountStep.CONFIRM },
            onBack = { step = CreateAccountStep.SETUP }
        )
        CreateAccountStep.CONFIRM -> ConfirmStep(
            keyName = keyName,
            mnemonicData = mnemonicData,
            onGetCipher = onGetCipher,
            onBiometricAuth = onBiometricAuth,
            onCreateAccount = onCreateAccount,
            onDismiss = onDismiss,
            onBack = { step = CreateAccountStep.SEED_WORDS },
            importState = importState
        )
    }
}

@Composable
private fun SetupStep(
    isGenerating: Boolean,
    generateError: String?,
    keyName: String,
    onKeyNameChange: (String) -> Unit,
    isInputEnabled: Boolean,
    onNext: () -> Unit,
    onRetry: () -> Unit,
    onDismiss: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Create Account",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(24.dp))

        if (generateError != null) {
            StatusCard(
                text = generateError,
                containerColor = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer
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
                    onClick = onRetry,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Retry")
                }
            }
        } else if (isGenerating) {
            CircularProgressIndicator()
            Spacer(modifier = Modifier.height(16.dp))
            Text("Generating seed words...")
        } else {
            StatusCard(
                text = "Seed words generated. Choose a name and continue to view them.",
                containerColor = MaterialTheme.colorScheme.primaryContainer,
                contentColor = MaterialTheme.colorScheme.onPrimaryContainer
            )

            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(
                value = keyName,
                onValueChange = onKeyNameChange,
                label = { Text("Key Name") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                enabled = isInputEnabled
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
                    onClick = onNext,
                    modifier = Modifier.weight(1f),
                    enabled = keyName.isNotBlank()
                ) {
                    Text("Next")
                }
            }
        }
    }
}

@Composable
private fun SeedWordsStep(
    mnemonicData: SecureShareData,
    onNext: () -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val words = mnemonicData.words()

    DisposableEffect(context) {
        setSecureScreen(context, true)
        onDispose { setSecureScreen(context, false) }
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
            text = "Seed Words",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(24.dp))

        val halfSize = words.size / 2

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            SeedWordColumn(words, 0 until halfSize, Modifier.weight(1f))
            SeedWordColumn(words, halfSize until words.size, Modifier.weight(1f))
        }

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedButton(
            onClick = { copySensitiveText(context, mnemonicData.valueUnsafe()) },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Copy to clipboard")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Write down these words and store them safely. Anyone with these words can access your account.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error
        )

        Spacer(modifier = Modifier.height(24.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier.weight(1f)
            ) {
                Text("Back")
            }
            Button(
                onClick = onNext,
                modifier = Modifier.weight(1f)
            ) {
                Text("I've saved my seed words")
            }
        }
    }
}

@Composable
private fun SeedWordColumn(words: List<String>, range: IntRange, modifier: Modifier) {
    Column(modifier = modifier) {
        for (i in range) {
            OutlinedTextField(
                value = words[i],
                onValueChange = {},
                readOnly = true,
                prefix = { Text("${i + 1}. ") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            if (i < range.last) {
                Spacer(modifier = Modifier.height(4.dp))
            }
        }
    }
}

@Composable
private fun ConfirmStep(
    keyName: String,
    mnemonicData: SecureShareData,
    onGetCipher: () -> Cipher,
    onBiometricAuth: (Cipher, (Cipher?) -> Unit) -> Unit,
    onCreateAccount: (mnemonic: String, passphrase: String, name: String, cipher: Cipher) -> Unit,
    onDismiss: () -> Unit,
    onBack: () -> Unit,
    importState: ImportState
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Create Account",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "Confirm you've saved your seed words",
            style = MaterialTheme.typography.bodyLarge
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
                text = "Account '${importState.name}' created successfully",
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
                canImport = mnemonicData.isNotBlank() && (importState is ImportState.Idle || importState is ImportState.Error),
                onDismiss = if (importState is ImportState.Success) onDismiss else onBack,
                onImportClick = { onError ->
                    try {
                        val cipher = onGetCipher()
                        onBiometricAuth(cipher) { authedCipher ->
                            if (authedCipher != null) {
                                onCreateAccount(mnemonicData.valueUnsafe(), "", keyName.trim(), authedCipher)
                            }
                        }
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        if (BuildConfig.DEBUG) Log.e("CreateAccount", "Biometric key invalidated: ${e::class.simpleName}")
                        onError("Biometric key invalidated. Please re-enroll biometrics.")
                    } catch (e: BiometricHelper.BiometricNotReadyException) {
                        if (BuildConfig.DEBUG) Log.e("CreateAccount", "Biometric not ready: ${e::class.simpleName}")
                        onError("Biometric authentication is unavailable")
                    } catch (e: Exception) {
                        if (BuildConfig.DEBUG) Log.e("CreateAccount", "Failed to initialize cipher: ${e::class.simpleName}")
                        onError("Failed to initialize encryption")
                    }
                }
            )
        }
    }
}
