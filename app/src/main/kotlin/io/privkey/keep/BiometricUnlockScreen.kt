package io.privkey.keep

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

@Composable
fun BiometricUnlockScreen(
    onAuthenticate: suspend () -> BiometricHelper.AuthResult,
    onUnlocked: () -> Unit
) {
    val context = LocalContext.current
    var authResult by remember { mutableStateOf<BiometricHelper.AuthResult?>(null) }
    val coroutineScope = rememberCoroutineScope()

    suspend fun attemptAuth() {
        authResult = null
        val result = onAuthenticate()
        if (result == BiometricHelper.AuthResult.SUCCESS) onUnlocked() else authResult = result
    }

    DisposableEffect(context) {
        setSecureScreen(context, true)
        onDispose { setSecureScreen(context, false) }
    }

    LaunchedEffect(Unit) { attemptAuth() }

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
                text = "Authenticate to unlock",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            val result = authResult
            if (result != null) {
                Spacer(modifier = Modifier.height(24.dp))

                when (result) {
                    BiometricHelper.AuthResult.LOCKOUT -> {
                        Text(
                            text = "Too many attempts. Try again shortly.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                    BiometricHelper.AuthResult.LOCKOUT_PERMANENT -> {
                        Text(
                            text = "Biometric locked. Use device PIN/password to unlock, then try again.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                    else -> {
                        Button(onClick = { coroutineScope.launch { attemptAuth() } }) {
                            Text("Try Again")
                        }
                    }
                }
            }
        }
    }
}
