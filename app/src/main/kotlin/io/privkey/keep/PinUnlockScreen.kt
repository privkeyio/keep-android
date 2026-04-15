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
import androidx.compose.ui.res.stringResource
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
    var biometricResetRequired by remember { mutableStateOf(pinStore.requiresBiometricReset()) }
    val focusRequester = remember { FocusRequester() }
    val coroutineScope = rememberCoroutineScope()
    val context = LocalContext.current
    val errTooMany = stringResource(R.string.pin_unlock_error_too_many)
    val errIncorrectFormat = stringResource(R.string.pin_unlock_error_incorrect)

    DisposableEffect(context) {
        setSecureScreen(context, true)
        onDispose { setSecureScreen(context, false) }
    }

    LaunchedEffect(isLockedOut) {
        if (!isLockedOut) return@LaunchedEffect
        val maxTicks = ((pinStore.getLockoutRemainingMs() / 1000) + 120).coerceAtLeast(120)
        repeat(maxTicks.toInt()) {
            lockoutRemaining = pinStore.getLockoutRemainingMs()
            if (lockoutRemaining <= 0) {
                isLockedOut = false
                error = null
                biometricResetRequired = pinStore.requiresBiometricReset()
                return@LaunchedEffect
            }
            delay(1000)
        }
        lockoutRemaining = pinStore.getLockoutRemainingMs()
        isLockedOut = pinStore.isLockedOut()
        if (!isLockedOut) {
            error = null
            biometricResetRequired = pinStore.requiresBiometricReset()
        }
    }

    LaunchedEffect(Unit) {
        if (!biometricResetRequired) {
            focusRequester.requestFocus()
        }
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
            error = errTooMany
        } else {
            error = String.format(errIncorrectFormat, pinStore.getRemainingAttempts())
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
                text = stringResource(R.string.pin_unlock_app_title),
                style = MaterialTheme.typography.headlineLarge
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = stringResource(R.string.pin_unlock_prompt),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(32.dp))

            if (biometricResetRequired && onBiometricAuth != null && !isLockedOut) {
                Text(
                    text = stringResource(R.string.pin_unlock_biometric_required_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.error
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.pin_unlock_biometric_required_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(24.dp))
                Button(
                    onClick = {
                        coroutineScope.launch {
                            if (onBiometricAuth()) {
                                pinStore.clearBiometricResetRequirement()
                                pinStore.refreshSession()
                                biometricResetRequired = false
                                onBiometricSuccess()
                                onUnlocked()
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(stringResource(R.string.pin_unlock_use_biometrics))
                }
            } else if (isLockedOut) {
                val seconds = (lockoutRemaining / 1000).toInt()
                Text(
                    text = stringResource(R.string.pin_unlock_locked_out_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.error
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.pin_unlock_locked_out_body, seconds),
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
                    label = { Text(stringResource(R.string.pin_unlock_label_pin)) },
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
                    Text(stringResource(R.string.pin_unlock_button))
                }

                onBiometricAuth?.let { auth ->
                    Spacer(modifier = Modifier.height(16.dp))
                    TextButton(onClick = {
                        coroutineScope.launch {
                            if (auth()) {
                                pinStore.refreshSession()
                                onBiometricSuccess()
                                onUnlocked()
                            }
                        }
                    }) {
                        Text(stringResource(R.string.pin_unlock_use_biometrics))
                    }
                }
            }
        }
    }
}
