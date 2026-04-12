package io.privkey.keep

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.password
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner

@Composable
internal fun SeedWordsScreen(
    mnemonicData: SecureShareData?,
    isLoading: Boolean,
    didBackup: Boolean,
    onConfirmBackedUp: () -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var showCopyWarning by remember { mutableStateOf(false) }

    DisposableEffect(context) {
        setSecureScreen(context, true)
        onDispose { setSecureScreen(context, false) }
    }

    DisposableEffect(lifecycleOwner, mnemonicData) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                mnemonicData?.clear()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    BackHandler { onDismiss() }

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

        Spacer(modifier = Modifier.height(16.dp))

        if (isLoading) {
            CircularProgressIndicator()
            Spacer(modifier = Modifier.height(24.dp))
            OutlinedButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Back")
            }
            return@Column
        }

        if (mnemonicData?.isNotBlank() != true) {
            StatusCard(
                text = "No seed words available for this account. Seed words are only available for accounts created from a mnemonic in this app.",
                containerColor = MaterialTheme.colorScheme.secondaryContainer,
                contentColor = MaterialTheme.colorScheme.onSecondaryContainer
            )

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Back")
            }
            return@Column
        }

        val words = mnemonicData.words()
        val halfSize = (words.size + 1) / 2

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            SeedWordColumn(words, 0 until halfSize, Modifier.weight(1f))
            SeedWordColumn(words, halfSize until words.size, Modifier.weight(1f))
        }

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedButton(
            onClick = { showCopyWarning = true },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Copy to clipboard")
        }

        if (showCopyWarning) {
            AlertDialog(
                onDismissRequest = { showCopyWarning = false },
                title = { Text("Copy seed words?") },
                text = { Text("Your seed words will be placed on the clipboard, where other apps may be able to read them. The clipboard will be cleared after 10 seconds.") },
                confirmButton = {
                    TextButton(onClick = {
                        showCopyWarning = false
                        copySensitiveText(context, mnemonicData.valueUnsafe())
                    }) { Text("Copy") }
                },
                dismissButton = {
                    TextButton(onClick = { showCopyWarning = false }) { Text("Cancel") }
                }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Write down these words and store them safely. Anyone with these words can access your account.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error
        )

        Spacer(modifier = Modifier.height(24.dp))

        if (!didBackup) {
            Button(
                onClick = onConfirmBackedUp,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("I've saved my seed words")
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Back")
            }
        } else {
            Button(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Back")
            }
        }
    }
}

@Composable
private fun SeedWordColumn(words: List<String>, range: IntRange, modifier: Modifier) {
    Column(modifier = modifier) {
        for (i in range) {
            if (i >= words.size) break
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(4.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .padding(horizontal = 12.dp, vertical = 10.dp)
                    .semantics { password() },
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "${i + 1}.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.width(28.dp)
                )
                Text(
                    text = words[i],
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
            if (i < range.last && i + 1 < words.size) {
                Spacer(modifier = Modifier.height(4.dp))
            }
        }
    }
}
