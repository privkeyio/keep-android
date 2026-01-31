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
    var pin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val focusRequester = remember { FocusRequester() }

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
                        value = pin,
                        onValueChange = { newValue ->
                            if (newValue.length <= PinStore.MAX_PIN_LENGTH && newValue.all { it.isDigit() }) {
                                pin = newValue
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
                            onNext = {
                                if (pin.length >= PinStore.MIN_PIN_LENGTH) {
                                    step = SetupStep.CONFIRM_PIN
                                }
                            }
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
                        onClick = {
                            if (pin.length < PinStore.MIN_PIN_LENGTH) {
                                error = "PIN must be at least ${PinStore.MIN_PIN_LENGTH} digits"
                            } else {
                                step = SetupStep.CONFIRM_PIN
                            }
                        },
                        enabled = pin.length >= PinStore.MIN_PIN_LENGTH,
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
                        value = confirmPin,
                        onValueChange = { newValue ->
                            if (newValue.length <= PinStore.MAX_PIN_LENGTH && newValue.all { it.isDigit() }) {
                                confirmPin = newValue
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
                            onDone = {
                                if (confirmPin == pin) {
                                    if (pinStore.setPin(pin)) {
                                        onPinSet()
                                    } else {
                                        error = "Failed to set PIN"
                                    }
                                } else {
                                    error = "PINs don't match"
                                    confirmPin = ""
                                }
                            }
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
                                confirmPin = ""
                                error = null
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Back")
                        }

                        Button(
                            onClick = {
                                if (confirmPin != pin) {
                                    error = "PINs don't match"
                                    confirmPin = ""
                                } else if (pinStore.setPin(pin)) {
                                    onPinSet()
                                } else {
                                    error = "Failed to set PIN"
                                }
                            },
                            enabled = confirmPin.length >= PinStore.MIN_PIN_LENGTH,
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
