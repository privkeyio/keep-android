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
    onAuthenticate: suspend () -> Boolean,
    onUnlocked: () -> Unit
) {
    val context = LocalContext.current
    var authFailed by remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()

    suspend fun attemptAuth() {
        authFailed = false
        if (onAuthenticate()) onUnlocked() else authFailed = true
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

            if (authFailed) {
                Spacer(modifier = Modifier.height(24.dp))

                Button(onClick = { coroutineScope.launch { attemptAuth() } }) {
                    Text("Try Again")
                }
            }
        }
    }
}
