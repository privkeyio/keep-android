package io.privkey.keep.nip46

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.privkey.keep.R
import io.privkey.keep.nip55.PermissionDuration
import io.privkey.keep.uniffi.Nip55RequestType

@Composable
internal fun Nip46DetailRow(
    label: String,
    value: String,
    valueMaxLines: Int = Int.MAX_VALUE
) {
    Text(
        text = label,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Text(
        text = value,
        style = MaterialTheme.typography.bodyLarge,
        maxLines = valueMaxLines,
        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
    )
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

@Composable
internal fun formatNip46Method(method: String): String = when (method) {
    "connect" -> stringResource(R.string.connections_nip46_method_connect)
    "get_public_key" -> stringResource(R.string.connections_nip46_method_get_public_key)
    "sign_event" -> stringResource(R.string.connections_nip46_method_sign_event)
    "nip44_encrypt" -> stringResource(R.string.connections_nip46_method_nip44_encrypt)
    "nip44_decrypt" -> stringResource(R.string.connections_nip46_method_nip44_decrypt)
    "nip44v3_encrypt" -> stringResource(R.string.connections_nip46_method_nip44_v3_encrypt)
    "nip44v3_decrypt" -> stringResource(R.string.connections_nip46_method_nip44_v3_decrypt)
    "nip04_encrypt" -> stringResource(R.string.connections_nip46_method_nip04_encrypt)
    "nip04_decrypt" -> stringResource(R.string.connections_nip46_method_nip04_decrypt)
    "ping" -> stringResource(R.string.connections_nip46_method_ping)
    else -> method
}

internal fun sanitizeDisplayName(name: String): String {
    return name
        .replace(Regex("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]"), "")
        .replace(Regex("[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u206F\\uFEFF]"), "")
        .take(50)
        .ifBlank { "Unknown App" }
}

internal fun mapMethodToNip55RequestType(method: String): Nip55RequestType? = when (method) {
    "sign_event" -> Nip55RequestType.SIGN_EVENT
    "nip44_encrypt" -> Nip55RequestType.NIP44_ENCRYPT
    "nip44_decrypt" -> Nip55RequestType.NIP44_DECRYPT
    "nip44v3_encrypt" -> Nip55RequestType.NIP44_V3_ENCRYPT
    "nip44v3_decrypt" -> Nip55RequestType.NIP44_V3_DECRYPT
    "nip04_encrypt" -> Nip55RequestType.NIP04_ENCRYPT
    "nip04_decrypt" -> Nip55RequestType.NIP04_DECRYPT
    "get_public_key" -> Nip55RequestType.GET_PUBLIC_KEY
    else -> null
}
