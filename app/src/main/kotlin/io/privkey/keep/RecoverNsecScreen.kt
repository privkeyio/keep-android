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
import io.privkey.keep.uniffi.recoverNsec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Arrays
import javax.crypto.Cipher

private const val MAX_SHARE_LENGTH = 8192
private const val AUTO_CLEAR_DELAY_MS = 60_000L
private const val RECOVERY_COOLDOWN_MS = 5_000L

sealed class RecoveryState {
    object Idle : RecoveryState()
    object Recovering : RecoveryState()
    data class Error(val message: String) : RecoveryState()
    data class Success(val nsec: CharArray) : RecoveryState() {
        fun clear() {
            Arrays.fill(nsec, '\u0000')
        }
    }
}

private class ShareSlot {
    val data = SecureShareData(MAX_SHARE_LENGTH)
    val passphrase = SecurePassphrase()
    var dataDisplay by mutableStateOf("")
    var passphraseDisplay by mutableStateOf("")

    fun clear() {
        data.clear()
        passphrase.clear()
        dataDisplay = ""
        passphraseDisplay = ""
    }

    fun hasContent(): Boolean = data.isNotBlank() && passphrase.length > 0
}

@Composable
fun RecoverNsecScreen(
    keepMobile: KeepMobile,
    storage: AndroidKeystoreStorage,
    shareInfo: ShareInfo?,
    allAccounts: List<AccountInfo>,
    onGetCipher: () -> Cipher?,
    onBiometricAuth: (Cipher, (Cipher?) -> Unit) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val coroutineScope = rememberCoroutineScope()

    val threshold = shareInfo?.threshold?.toInt() ?: 2
    val totalShares = shareInfo?.totalShares?.toInt() ?: 3
    val groupPubkey = shareInfo?.groupPubkey

    var recoveryState by remember { mutableStateOf<RecoveryState>(RecoveryState.Idle) }
    var nsecVisible by remember { mutableStateOf(false) }
    var autoClearRemaining by remember { mutableIntStateOf(0) }
    var lastAttemptTime by remember { mutableLongStateOf(0L) }
    var showScanner by remember { mutableStateOf<Int?>(null) }
    var vaultSlotPopulated by remember { mutableStateOf(false) }
    var isPreFilling by remember { mutableStateOf(false) }

    val slots = remember {
        mutableStateListOf<ShareSlot>().apply {
            repeat(threshold) { add(ShareSlot()) }
        }
    }

    fun clearAll() {
        slots.forEach { it.clear() }
        (recoveryState as? RecoveryState.Success)?.clear()
        recoveryState = RecoveryState.Idle
        nsecVisible = false
        autoClearRemaining = 0
        vaultSlotPopulated = false
        isPreFilling = false
    }

    DisposableEffect(lifecycleOwner) {
        setSecureScreen(context, true)

        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_PAUSE) {
                clearAll()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            clearAll()
            setSecureScreen(context, false)
            lifecycleOwner.lifecycle.removeObserver(observer)
        }
    }

    LaunchedEffect(recoveryState) {
        if (recoveryState is RecoveryState.Success) {
            autoClearRemaining = (AUTO_CLEAR_DELAY_MS / 1000).toInt()
            while (autoClearRemaining > 0) {
                delay(1000)
                autoClearRemaining--
            }
            clearAll()
        }
    }

    val scannerSlot = showScanner
    if (scannerSlot != null) {
        QrScannerScreen(
            onCodeScanned = { code ->
                if (scannerSlot < slots.size) {
                    slots[scannerSlot].data.update(code)
                    slots[scannerSlot].dataDisplay = code
                }
                showScanner = null
            },
            onDismiss = { showScanner = null },
            validator = ::isValidKshareFormat,
            title = "Scan Share QR Code"
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
            text = "Recover nsec",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        if (groupPubkey != null) {
            Text(
                text = "$threshold of $totalShares shares needed",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
        ) {
            Text(
                text = "This recovers the full private key from threshold shares. " +
                    "The key is a single point of failure \u2014 handle with extreme care. " +
                    "It will not be saved.",
                modifier = Modifier.padding(16.dp),
                color = MaterialTheme.colorScheme.onErrorContainer,
                style = MaterialTheme.typography.bodySmall
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        if (shareInfo != null && !vaultSlotPopulated) {
            OutlinedButton(
                onClick = {
                    val cipher = onGetCipher()
                    if (cipher == null) {
                        recoveryState = RecoveryState.Error("No encryption key available")
                        return@OutlinedButton
                    }
                    onBiometricAuth(cipher) { authedCipher ->
                        if (authedCipher != null) {
                            isPreFilling = true
                            coroutineScope.launch {
                                val exportId = java.util.UUID.randomUUID().toString()
                                storage.setPendingCipher(exportId, authedCipher)
                                try {
                                    val ephemeralPass = java.util.UUID.randomUUID().toString()
                                    val exported = withContext(Dispatchers.IO) {
                                        storage.setRequestIdContext(exportId)
                                        try {
                                            keepMobile.exportShare(ephemeralPass)
                                        } finally {
                                            storage.clearRequestIdContext()
                                        }
                                    }
                                    if (slots.isNotEmpty()) {
                                        slots[0].data.update(exported)
                                        slots[0].passphrase.update(ephemeralPass)
                                        slots[0].dataDisplay = exported
                                        slots[0].passphraseDisplay = ephemeralPass
                                        vaultSlotPopulated = true
                                    }
                                } catch (e: Exception) {
                                    if (BuildConfig.DEBUG) Log.e("RecoverNsec", "Vault export failed: ${e::class.simpleName}")
                                    recoveryState = RecoveryState.Error("Failed to export vault share")
                                } finally {
                                    storage.clearPendingCipher(exportId)
                                    isPreFilling = false
                                }
                            }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = recoveryState !is RecoveryState.Recovering && !isPreFilling
            ) {
                Text("Pre-fill from vault share")
            }

            Spacer(modifier = Modifier.height(16.dp))
        }

        val isInputEnabled = recoveryState !is RecoveryState.Recovering &&
            recoveryState !is RecoveryState.Success

        slots.forEachIndexed { index, slot ->
            val isVault = vaultSlotPopulated && index == 0

            val cardColors = if (isVault) {
                CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
            } else {
                CardDefaults.cardColors()
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = cardColors
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    val shareLabel = if (isVault) "Share ${index + 1} (from vault)" else "Share ${index + 1}"
                    val labelColor = if (isVault) MaterialTheme.colorScheme.onPrimaryContainer
                        else MaterialTheme.colorScheme.onSurface

                    Text(
                        text = shareLabel,
                        style = MaterialTheme.typography.titleSmall,
                        color = labelColor
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedTextField(
                        value = slot.dataDisplay,
                        onValueChange = { value ->
                            if (value.length <= MAX_SHARE_LENGTH && !isVault) {
                                slots[index].data.update(value)
                                slots[index].dataDisplay = value
                            }
                        },
                        label = { Text("Share Data") },
                        placeholder = { Text("kshare1q...") },
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 2,
                        maxLines = 3,
                        enabled = isInputEnabled && !isVault
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    if (!isVault) {
                        OutlinedButton(
                            onClick = { showScanner = index },
                            modifier = Modifier.fillMaxWidth(),
                            enabled = isInputEnabled
                        ) {
                            Text("Scan QR Code")
                        }

                        Spacer(modifier = Modifier.height(8.dp))
                    }

                    OutlinedTextField(
                        value = slot.passphraseDisplay,
                        onValueChange = { value ->
                            if (!isVault) {
                                slots[index].passphrase.update(value)
                                slots[index].passphraseDisplay = value
                            }
                        },
                        label = { Text("Passphrase") },
                        modifier = Modifier.fillMaxWidth(),
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        singleLine = true,
                        enabled = isInputEnabled && !isVault
                    )

                    if (slots.size > 1 && !isVault) {
                        Spacer(modifier = Modifier.height(8.dp))
                        TextButton(
                            onClick = {
                                slots[index].clear()
                                slots.removeAt(index)
                            },
                            enabled = isInputEnabled
                        ) {
                            Text("Remove", color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
        }

        if (slots.size < totalShares) {
            TextButton(
                onClick = { slots.add(ShareSlot()) },
                enabled = isInputEnabled
            ) {
                Text("+ Add share input")
            }

            Spacer(modifier = Modifier.height(16.dp))
        }

        when (val state = recoveryState) {
            is RecoveryState.Error -> {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
                ) {
                    Text(
                        text = state.message,
                        modifier = Modifier.padding(16.dp),
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
                Spacer(modifier = Modifier.height(16.dp))
            }
            is RecoveryState.Success -> {
                NsecResultCard(
                    nsec = state.nsec,
                    visible = nsecVisible,
                    autoClearSeconds = autoClearRemaining,
                    onToggleVisibility = { nsecVisible = !nsecVisible },
                    onCopy = {
                        copySensitiveText(context, String(state.nsec))
                        Toast.makeText(context, "nsec copied", Toast.LENGTH_SHORT).show()
                    },
                    onClear = { clearAll() }
                )
                Spacer(modifier = Modifier.height(16.dp))
            }
            else -> {}
        }

        val filledSlots = slots.count { it.hasContent() }
        val canRecover = filledSlots >= threshold &&
            recoveryState !is RecoveryState.Recovering &&
            recoveryState !is RecoveryState.Success

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            OutlinedButton(
                onClick = {
                    clearAll()
                    onDismiss()
                },
                modifier = Modifier.weight(1f)
            ) {
                Text("Cancel")
            }

            if (recoveryState !is RecoveryState.Success) {
                Button(
                    onClick = {
                        val now = System.currentTimeMillis()
                        if (now - lastAttemptTime < RECOVERY_COOLDOWN_MS) {
                            recoveryState = RecoveryState.Error("Please wait before trying again")
                            return@Button
                        }
                        lastAttemptTime = now

                        val filled = slots.filter { it.hasContent() }
                        val shareDataList = filled.map { it.data.valueUnsafe() }
                        val passphraseList = filled.map { String(it.passphrase.toCharArray()) }

                        val groupPk = try {
                            groupPubkey?.let { hex ->
                                if (hex.isEmpty() || hex.length % 2 != 0 || !hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
                                    recoveryState = RecoveryState.Error("Invalid group public key")
                                    return@Button
                                }
                                hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                            }
                        } catch (_: NumberFormatException) {
                            recoveryState = RecoveryState.Error("Invalid group public key")
                            return@Button
                        }

                        recoveryState = RecoveryState.Recovering
                        coroutineScope.launch {
                            try {
                                val nsec = withContext(Dispatchers.IO) {
                                    recoverNsec(shareDataList, passphraseList, groupPk)
                                }
                                slots.forEach { it.clear() }
                                recoveryState = RecoveryState.Success(nsec.toCharArray())
                            } catch (e: Exception) {
                                if (BuildConfig.DEBUG) Log.e("RecoverNsec", "Recovery failed: ${e::class.simpleName}")
                                recoveryState = RecoveryState.Error(
                                    mapRecoveryError(e.message ?: "Recovery failed")
                                )
                            }
                        }
                    },
                    modifier = Modifier.weight(1f),
                    enabled = canRecover
                ) {
                    Text("Recover")
                }
            }
        }

        if (recoveryState is RecoveryState.Recovering) {
            Spacer(modifier = Modifier.height(16.dp))
            CircularProgressIndicator()
            Spacer(modifier = Modifier.height(8.dp))
            Text("Recovering key...")
        }

        Spacer(modifier = Modifier.height(24.dp))
    }
}

@Composable
private fun NsecResultCard(
    nsec: CharArray,
    visible: Boolean,
    autoClearSeconds: Int,
    onToggleVisibility: () -> Unit,
    onCopy: () -> Unit,
    onClear: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Recovered nsec",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onPrimaryContainer
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = if (visible) String(nsec) else "\u2022".repeat(24),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer
            )

            Spacer(modifier = Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(onClick = onToggleVisibility) {
                    Text(if (visible) "Hide" else "Reveal")
                }
                OutlinedButton(onClick = onCopy) {
                    Text("Copy")
                }
                OutlinedButton(onClick = onClear) {
                    Text("Clear")
                }
            }

            if (autoClearSeconds > 0) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Auto-clears in ${autoClearSeconds}s \u2014 copy to a secure password manager",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}

private fun mapRecoveryError(message: String): String = when {
    message.contains("decrypt", ignoreCase = true) -> "Failed to decrypt share (wrong passphrase?)"
    message.contains("Duplicate", ignoreCase = true) -> "Duplicate share \u2014 each share must be unique"
    message.contains("same group", ignoreCase = true) -> "All shares must belong to the same group"
    message.contains("match", ignoreCase = true) -> "Recovered key does not match expected group"
    message.contains("format", ignoreCase = true) -> "Invalid share format"
    message.contains("threshold", ignoreCase = true) -> "Not enough shares to recover"
    else -> "Recovery failed"
}
