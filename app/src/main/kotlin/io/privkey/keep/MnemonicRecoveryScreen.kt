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
private const val PASTE_TOO_MANY_WORDS = "Pasted text has too many words (max 24)"

@Suppress("DEPRECATION")
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
    var pasteError by remember { mutableStateOf<String?>(null) }
    val mnemonicData = remember { SecureShareData(MAX_MNEMONIC_LENGTH) }

    val isInputEnabled = importState is ImportState.Idle || importState is ImportState.Error
    val focusRequesters = remember(wordCount) { List(wordCount) { FocusRequester() } }

    fun updateWordCount(newCount: Int) {
        wordCount = newCount
        while (words.size < newCount) words.add("")
        while (words.size > newCount) words.removeLast()
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
            WordInputColumn(
                range = 0 until halfSize,
                words = words,
                wordCount = wordCount,
                focusRequesters = focusRequesters,
                enabled = isInputEnabled,
                clipboardManager = clipboardManager,
                onUpdateWordCount = ::updateWordCount,
                onClearValidation = { validationError = null; pasteError = null },
                onPasteRejected = { pasteError = PASTE_TOO_MANY_WORDS },
                modifier = Modifier.weight(1f)
            )
            WordInputColumn(
                range = halfSize until wordCount,
                words = words,
                wordCount = wordCount,
                focusRequesters = focusRequesters,
                enabled = isInputEnabled,
                clipboardManager = clipboardManager,
                onUpdateWordCount = ::updateWordCount,
                onClearValidation = { validationError = null; pasteError = null },
                onPasteRejected = { pasteError = PASTE_TOO_MANY_WORDS },
                modifier = Modifier.weight(1f)
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        pasteError?.let { error ->
            StatusCard(
                text = error,
                containerColor = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer
            )
            Spacer(modifier = Modifier.height(16.dp))
        }

        validationError?.let { error ->
            StatusCard(
                text = error,
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
                canImport = filledCount == wordCount && keyName.isNotBlank() && isInputEnabled,
                onDismiss = onDismiss,
                onImportClick = { onError ->
                    val name = keyName.trim()
                    if (name.isBlank()) return@ImportButtons
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
                                onCreateAccount(mnemonicData.valueUnsafe(), "", name, authedCipher)
                            }
                        }
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        if (BuildConfig.DEBUG) Log.e("MnemonicRecovery", "Biometric key invalidated: ${e::class.simpleName}")
                        onError("Biometric key invalidated. Please re-enroll biometrics.")
                    } catch (e: BiometricHelper.BiometricNotReadyException) {
                        onError("Biometric authentication is unavailable")
                    } catch (e: Exception) {
                        if (BuildConfig.DEBUG) Log.e("MnemonicRecovery", "Failed to initialize cipher: ${e::class.simpleName}")
                        onError("Failed to initialize encryption")
                    }
                }
            )
        }
    }
}

@Suppress("DEPRECATION")
@Composable
private fun WordInputColumn(
    range: IntRange,
    words: MutableList<String>,
    wordCount: Int,
    focusRequesters: List<FocusRequester>,
    enabled: Boolean,
    clipboardManager: androidx.compose.ui.platform.ClipboardManager,
    onUpdateWordCount: (Int) -> Unit,
    onClearValidation: () -> Unit,
    onPasteRejected: () -> Unit,
    modifier: Modifier
) {
    Column(modifier = modifier) {
        for (i in range) {
            WordInputField(
                index = i,
                value = words[i],
                onValueChange = { newValue ->
                    val trimmed = newValue.trim()
                    if (trimmed.contains(" ")) {
                        handlePaste(trimmed, i, words, wordCount, onUpdateWordCount, onPasteRejected)
                    } else {
                        words[i] = newValue.lowercase().filter { it.isLetter() }
                    }
                    onClearValidation()
                },
                focusRequester = focusRequesters[i],
                onNext = {
                    if (i + 1 < focusRequesters.size) {
                        focusRequesters[i + 1].requestFocus()
                    }
                },
                enabled = enabled,
                onPaste = {
                    val clip = clipboardManager.getText()?.text ?: return@WordInputField
                    val pasteWords = clip.trim().split("\\s+".toRegex())
                    if (pasteWords.size > 1) {
                        handlePaste(clip, i, words, wordCount, onUpdateWordCount, onPasteRejected)
                        onClearValidation()
                    }
                }
            )
            if (i < range.last) {
                Spacer(modifier = Modifier.height(4.dp))
            }
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
                onValueChange(newValue)
                if (newValue.contains(" ")) onNext()
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
    wordCount: Int,
    onWordCountChange: (Int) -> Unit,
    onPasteRejected: (() -> Unit)? = null
) {
    val pasteWords = text.trim().lowercase().split("\\s+".toRegex())
        .map { it.filter { c -> c.isLetter() } }
        .filter { it.isNotEmpty() }
    if (pasteWords.size > 24) {
        onPasteRejected?.invoke()
        return
    }
    val effectiveStart = if (pasteWords.size in setOf(12, 24) && startIndex > 0) 0 else startIndex
    if (effectiveStart + pasteWords.size > 24) {
        onPasteRejected?.invoke()
        return
    }
    val totalNeeded = effectiveStart + pasteWords.size
    var effectiveWordCount = wordCount
    val newCount = if (pasteWords.size in setOf(12, 24) && startIndex == 0) pasteWords.size
        else if (totalNeeded > wordCount) 24
        else wordCount
    if (newCount != wordCount) {
        onWordCountChange(newCount)
        effectiveWordCount = newCount
    }
    pasteWords.forEachIndexed { i, word ->
        val targetIndex = effectiveStart + i
        if (targetIndex < effectiveWordCount) {
            words[targetIndex] = word
        }
    }
}
