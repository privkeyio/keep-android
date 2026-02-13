package io.privkey.keep.nip46

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.privkey.keep.nip55.PermissionDuration
import io.privkey.keep.uniffi.Nip55RequestType

@Composable
internal fun Nip46DetailRow(label: String, value: String) {
    Text(
        text = label,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Text(text = value, style = MaterialTheme.typography.bodyLarge)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun PermissionDurationSelector(
    label: String,
    selectedDuration: PermissionDuration,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    onDurationSelected: (PermissionDuration) -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(4.dp))
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = onExpandedChange
        ) {
            OutlinedTextField(
                value = stringResource(selectedDuration.displayNameRes),
                onValueChange = {},
                readOnly = true,
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier
                    .fillMaxWidth()
                    .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable)
            )
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { onExpandedChange(false) }
            ) {
                PermissionDuration.entries.forEach { duration ->
                    DropdownMenuItem(
                        text = { Text(stringResource(duration.displayNameRes)) },
                        onClick = {
                            onDurationSelected(duration)
                            onExpandedChange(false)
                        }
                    )
                }
            }
        }
    }
}

internal fun formatNip46Method(method: String): String = when (method) {
    "connect" -> "Connect"
    "get_public_key" -> "Get Public Key"
    "sign_event" -> "Sign Event"
    "nip44_encrypt" -> "Encrypt (NIP-44)"
    "nip44_decrypt" -> "Decrypt (NIP-44)"
    "nip04_encrypt" -> "Encrypt (NIP-04)"
    "nip04_decrypt" -> "Decrypt (NIP-04)"
    "ping" -> "Ping"
    else -> method
}

internal fun mapMethodToNip55RequestType(method: String): Nip55RequestType? = when (method) {
    "sign_event" -> Nip55RequestType.SIGN_EVENT
    "nip44_encrypt" -> Nip55RequestType.NIP44_ENCRYPT
    "nip44_decrypt" -> Nip55RequestType.NIP44_DECRYPT
    "nip04_encrypt" -> Nip55RequestType.NIP04_ENCRYPT
    "nip04_decrypt" -> Nip55RequestType.NIP04_DECRYPT
    "get_public_key" -> Nip55RequestType.GET_PUBLIC_KEY
    else -> null
}
