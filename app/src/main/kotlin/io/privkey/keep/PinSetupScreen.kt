package io.privkey.keep

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.privkey.keep.storage.PinStore

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PinSetupScreen(
    pinStore: PinStore,
    onPinSet: () -> Unit,
    onDismiss: () -> Unit
) {
    var step by remember { mutableStateOf(SetupStep.ENTER_PIN) }
    var pinInput by remember { mutableStateOf("") }
    var confirmPinInput by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val focusRequester = remember { FocusRequester() }

    fun validateAndProceed(): Boolean {
        if (pinInput.length < PinStore.MIN_PIN_LENGTH) {
            error = "PIN must be at least ${PinStore.MIN_PIN_LENGTH} digits"
            return false
        }
        if (pinStore.isWeakPin(pinInput)) {
            error = "PIN is too simple. Avoid patterns like 1234 or 0000."
            return false
        }
        step = SetupStep.CONFIRM_PIN
        return true
    }

    fun confirmAndSetPin(): Boolean {
        if (confirmPinInput != pinInput) {
            error = "PINs don't match"
            confirmPinInput = ""
            return false
        }
        if (pinStore.isWeakPin(pinInput)) {
            error = "PIN is too simple"
            step = SetupStep.ENTER_PIN
            pinInput = ""
            confirmPinInput = ""
            return false
        }
        val result = pinStore.setPin(pinInput)
        pinInput = ""
        confirmPinInput = ""
        if (result) {
            onPinSet()
            return true
        }
        error = "Failed to set PIN"
        return false
    }

    LaunchedEffect(step) {
        focusRequester.requestFocus()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Set Up PIN") },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            when (step) {
                SetupStep.ENTER_PIN -> {
                    Text(
                        text = "Enter a ${PinStore.MIN_PIN_LENGTH}-${PinStore.MAX_PIN_LENGTH} digit PIN",
                        style = MaterialTheme.typography.bodyLarge
                    )

                    Spacer(modifier = Modifier.height(24.dp))

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
                            imeAction = ImeAction.Next
                        ),
                        keyboardActions = KeyboardActions(
                            onNext = { validateAndProceed() }
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
                            color = MaterialTheme.colorScheme.error
                        )
                    }

                    Spacer(modifier = Modifier.height(24.dp))

                    Button(
                        onClick = { validateAndProceed() },
                        enabled = pinInput.length >= PinStore.MIN_PIN_LENGTH,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Next")
                    }
                }

                SetupStep.CONFIRM_PIN -> {
                    Text(
                        text = "Confirm your PIN",
                        style = MaterialTheme.typography.bodyLarge
                    )

                    Spacer(modifier = Modifier.height(24.dp))

                    OutlinedTextField(
                        value = confirmPinInput,
                        onValueChange = { newValue ->
                            if (newValue.length <= PinStore.MAX_PIN_LENGTH && newValue.all { it.isDigit() }) {
                                confirmPinInput = newValue
                                error = null
                            }
                        },
                        label = { Text("Confirm PIN") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.NumberPassword,
                            imeAction = ImeAction.Done
                        ),
                        keyboardActions = KeyboardActions(
                            onDone = { confirmAndSetPin() }
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
                            color = MaterialTheme.colorScheme.error
                        )
                    }

                    Spacer(modifier = Modifier.height(24.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                step = SetupStep.ENTER_PIN
                                confirmPinInput = ""
                                error = null
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Back")
                        }

                        Button(
                            onClick = { confirmAndSetPin() },
                            enabled = confirmPinInput.length >= PinStore.MIN_PIN_LENGTH,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Set PIN")
                        }
                    }
                }
            }
        }
    }
}

private enum class SetupStep {
    ENTER_PIN,
    CONFIRM_PIN
}
