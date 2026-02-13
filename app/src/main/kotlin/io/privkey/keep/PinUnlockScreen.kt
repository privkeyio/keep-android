package io.privkey.keep

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.privkey.keep.storage.PinStore
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Composable
fun PinUnlockScreen(
    pinStore: PinStore,
    onUnlocked: () -> Unit,
    onBiometricAuth: (suspend () -> Boolean)? = null,
    onBiometricSuccess: () -> Unit = {}
) {
    var pinInput by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var isLockedOut by remember { mutableStateOf(pinStore.isLockedOut()) }
    var lockoutRemaining by remember { mutableStateOf(pinStore.getLockoutRemainingMs()) }
    val focusRequester = remember { FocusRequester() }
    val coroutineScope = rememberCoroutineScope()
    val context = LocalContext.current

    DisposableEffect(context) {
        setSecureScreen(context, true)
        onDispose { setSecureScreen(context, false) }
    }

    LaunchedEffect(isLockedOut) {
        repeat(3600) {
            if (!isLockedOut) return@LaunchedEffect
            lockoutRemaining = pinStore.getLockoutRemainingMs()
            if (lockoutRemaining <= 0) {
                isLockedOut = false
                error = null
                return@LaunchedEffect
            }
            delay(1000)
        }
    }

    LaunchedEffect(Unit) {
        focusRequester.requestFocus()
    }

    fun verifyAndUnlock() {
        if (pinInput.isEmpty()) return

        val verified = pinStore.verifyPin(pinInput)
        pinInput = ""

        if (verified) {
            onUnlocked()
            return
        }

        if (pinStore.isLockedOut()) {
            isLockedOut = true
            error = "Too many attempts. Try again later."
        } else {
            error = "Incorrect PIN. ${pinStore.getRemainingAttempts()} attempts remaining."
        }
    }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "Keep",
                style = MaterialTheme.typography.headlineLarge
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Enter PIN to unlock",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(32.dp))

            if (isLockedOut) {
                val seconds = (lockoutRemaining / 1000).toInt()
                Text(
                    text = "Locked out",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.error
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Try again in $seconds seconds",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                OutlinedTextField(
                    value = pinInput,
                    onValueChange = { newValue ->
                        if (newValue.length <= PinStore.MAX_PIN_LENGTH && newValue.all { it.isDigit() }) {
                            pinInput = newValue
                            error = null
                        }
                    },
                    label = { Text("PIN") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.NumberPassword,
                        imeAction = ImeAction.Done
                    ),
                    keyboardActions = KeyboardActions(
                        onDone = { verifyAndUnlock() }
                    ),
                    isError = error != null,
                    modifier = Modifier
                        .fillMaxWidth()
                        .focusRequester(focusRequester)
                )

                error?.let {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = it,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        textAlign = TextAlign.Center
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                Button(
                    onClick = { verifyAndUnlock() },
                    enabled = pinInput.length >= PinStore.MIN_PIN_LENGTH,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Unlock")
                }

                onBiometricAuth?.let { auth ->
                    Spacer(modifier = Modifier.height(16.dp))
                    TextButton(onClick = {
                        coroutineScope.launch {
                            if (auth()) {
                                onBiometricSuccess()
                                onUnlocked()
                            }
                        }
                    }) {
                        Text("Use Biometrics")
                    }
                }
            }
        }
    }
}
