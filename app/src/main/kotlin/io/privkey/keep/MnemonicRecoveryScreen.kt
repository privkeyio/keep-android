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
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.PopupProperties
import io.privkey.keep.uniffi.KeepMobile
import javax.crypto.Cipher

private const val MAX_MNEMONIC_LENGTH = 1024

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MnemonicRecoveryScreen(
    keepMobile: KeepMobile,
    onCreateAccount: (mnemonic: String, passphrase: String, name: String, cipher: Cipher) -> Unit,
    onGetCipher: () -> Cipher,
    onBiometricAuth: (Cipher, (Cipher?) -> Unit) -> Unit,
    onDismiss: () -> Unit,
    importState: ImportState
) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    var wordCount by remember { mutableIntStateOf(12) }
    val words = remember { mutableStateListOf(*Array(12) { "" }) }
    var keyName by remember { mutableStateOf("Mobile Key") }
    var validationError by remember { mutableStateOf<String?>(null) }
    val mnemonicData = remember { SecureShareData(MAX_MNEMONIC_LENGTH) }

    val isInputEnabled = importState is ImportState.Idle || importState is ImportState.Error
    val focusRequesters = remember(wordCount) { List(wordCount) { FocusRequester() } }

    fun updateWordCount(newCount: Int) {
        wordCount = newCount
        while (words.size < newCount) words.add("")
        while (words.size > newCount) words.removeAt(words.lastIndex)
    }

    DisposableEffect(context) {
        setSecureScreen(context, true)
        onDispose { setSecureScreen(context, false) }
    }

    LaunchedEffect(importState) {
        if (importState is ImportState.Success) {
            mnemonicData.clear()
            words.indices.forEach { words[it] = "" }
        }
    }

    DisposableEffect(Unit) {
        onDispose {
            mnemonicData.clear()
            words.indices.forEach { words[it] = "" }
        }
    }

    val filledCount = words.count { it.isNotBlank() }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Import from Seed Words",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(16.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = wordCount == 12,
                onClick = { updateWordCount(12) },
                label = { Text("12 words") },
                enabled = isInputEnabled
            )
            FilterChip(
                selected = wordCount == 24,
                onClick = { updateWordCount(24) },
                label = { Text("24 words") },
                enabled = isInputEnabled
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "$filledCount of $wordCount words entered",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = keyName,
            onValueChange = { if (it.length <= 64) keyName = it },
            label = { Text("Key Name") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            enabled = isInputEnabled
        )

        Spacer(modifier = Modifier.height(16.dp))

        val halfSize = wordCount / 2

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Column(modifier = Modifier.weight(1f)) {
                for (i in 0 until halfSize) {
                    WordInputField(
                        index = i,
                        value = words[i],
                        onValueChange = { newValue ->
                            val trimmed = newValue.trim()
                            if (trimmed.contains(" ")) {
                                handlePaste(trimmed, i, words, wordCount)
                            } else {
                                words[i] = newValue.lowercase().filter { it.isLetter() }
                            }
                            validationError = null
                        },
                        focusRequester = focusRequesters[i],
                        onNext = {
                            if (i + 1 < wordCount) {
                                focusRequesters[i + 1].requestFocus()
                            }
                        },
                        enabled = isInputEnabled,
                        onPaste = {
                            val clip = clipboardManager.getText()?.text ?: return@WordInputField
                            val pasteWords = clip.trim().split("\\s+".toRegex())
                            if (pasteWords.size > 1) {
                                handlePaste(clip, i, words, wordCount)
                                validationError = null
                            }
                        }
                    )
                    if (i < halfSize - 1) {
                        Spacer(modifier = Modifier.height(4.dp))
                    }
                }
            }
            Column(modifier = Modifier.weight(1f)) {
                for (i in halfSize until wordCount) {
                    WordInputField(
                        index = i,
                        value = words[i],
                        onValueChange = { newValue ->
                            val trimmed = newValue.trim()
                            if (trimmed.contains(" ")) {
                                handlePaste(trimmed, i, words, wordCount)
                            } else {
                                words[i] = newValue.lowercase().filter { it.isLetter() }
                            }
                            validationError = null
                        },
                        focusRequester = focusRequesters[i],
                        onNext = {
                            if (i + 1 < wordCount) {
                                focusRequesters[i + 1].requestFocus()
                            }
                        },
                        enabled = isInputEnabled,
                        onPaste = {
                            val clip = clipboardManager.getText()?.text ?: return@WordInputField
                            val pasteWords = clip.trim().split("\\s+".toRegex())
                            if (pasteWords.size > 1) {
                                handlePaste(clip, i, words, wordCount)
                                validationError = null
                            }
                        }
                    )
                    if (i < wordCount - 1) {
                        Spacer(modifier = Modifier.height(4.dp))
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        val currentValidationError = validationError
        if (currentValidationError != null) {
            StatusCard(
                text = currentValidationError,
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
                canImport = filledCount == wordCount && isInputEnabled,
                onDismiss = onDismiss,
                onImportClick = { onError ->
                    val mnemonic = words.joinToString(" ")
                    try {
                        keepMobile.validateMnemonic(mnemonic)
                    } catch (e: Exception) {
                        validationError = "Invalid seed words. Please check and try again."
                        return@ImportButtons
                    }
                    mnemonicData.update(mnemonic)
                    try {
                        val cipher = onGetCipher()
                        onBiometricAuth(cipher) { authedCipher ->
                            if (authedCipher != null) {
                                onCreateAccount(mnemonicData.valueUnsafe(), "", keyName, authedCipher)
                            }
                        }
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        if (BuildConfig.DEBUG) Log.e("MnemonicRecovery", "Biometric key invalidated: ${e::class.simpleName}")
                        onError("Biometric key invalidated. Please re-enroll biometrics.")
                    } catch (e: BiometricHelper.BiometricNotReadyException) {
                        onError(e.message ?: "Biometric authentication is unavailable")
                    } catch (e: Exception) {
                        if (BuildConfig.DEBUG) Log.e("MnemonicRecovery", "Failed to initialize cipher: ${e::class.simpleName}: ${e.message}", e)
                        onError("Failed to initialize encryption")
                    }
                }
            )
        }
    }
}

@Composable
private fun WordInputField(
    index: Int,
    value: String,
    onValueChange: (String) -> Unit,
    focusRequester: FocusRequester,
    onNext: () -> Unit,
    enabled: Boolean,
    onPaste: () -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val suggestions = remember(value) {
        if (value.length >= 2) {
            BIP39_WORD_LIST.filter { it.startsWith(value) }.take(5)
        } else {
            emptyList()
        }
    }

    LaunchedEffect(value) {
        expanded = suggestions.isNotEmpty() && value.length >= 2 && value !in BIP39_WORD_LIST
    }

    Box {
        OutlinedTextField(
            value = value,
            onValueChange = { newValue ->
                if (newValue.contains(" ")) {
                    val trimmed = newValue.trim().replace(" ", "")
                    if (trimmed.isNotEmpty()) {
                        onValueChange(newValue)
                    }
                    onNext()
                } else {
                    onValueChange(newValue)
                }
            },
            prefix = { Text("${index + 1}. ") },
            modifier = Modifier
                .fillMaxWidth()
                .focusRequester(focusRequester),
            singleLine = true,
            enabled = enabled
        )

        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            properties = PopupProperties(focusable = false)
        ) {
            suggestions.forEach { suggestion ->
                DropdownMenuItem(
                    text = { Text(suggestion) },
                    onClick = {
                        onValueChange(suggestion)
                        expanded = false
                        onNext()
                    }
                )
            }
        }
    }
}

private fun handlePaste(
    text: String,
    startIndex: Int,
    words: MutableList<String>,
    wordCount: Int
) {
    val pasteWords = text.trim().lowercase().split("\\s+".toRegex())
    pasteWords.forEachIndexed { i, word ->
        val targetIndex = startIndex + i
        if (targetIndex < wordCount) {
            words[targetIndex] = word.filter { it.isLetter() }
        }
    }
}
