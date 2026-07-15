package io.privkey.keep.nip46

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.privkey.keep.R
import io.privkey.keep.uniffi.formatPubkeyDisplay
import io.privkey.keep.nip55.EventKind
import io.privkey.keep.nip55.PermissionDuration
import io.privkey.keep.ui.components.AppAvatar
import io.privkey.keep.ui.components.CopyableValue

private fun sanitizeDisplayContent(content: String): String {
    return content
        .replace(Regex("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]"), "\uFFFD")
        .replace(Regex("[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u206F\\uFEFF]"), "")
        .replace(Regex("[\\u0300-\\u036F]+"), "")
        .take(500)
}

@Composable
fun Nip46ApprovalScreen(
    appPubkey: String,
    appName: String,
    method: String,
    eventKind: Int?,
    eventContent: String?,
    isConnectRequest: Boolean = false,
    httpAuthUrl: String? = null,
    httpAuthMethod: String? = null,
    onApprove: (duration: PermissionDuration, onComplete: (success: Boolean) -> Unit) -> Unit,
    onReject: () -> Unit
) {
    val context = LocalContext.current
    var isLoading by remember { mutableStateOf(false) }
    var selectedDuration by remember { mutableStateOf(if (isConnectRequest) PermissionDuration.FOREVER else PermissionDuration.JUST_THIS_TIME) }
    var durationDropdownExpanded by remember { mutableStateOf(false) }
    val sanitizedContent = remember(eventContent) {
        eventContent?.let { sanitizeDisplayContent(it) }
    }
    // NIP-98 (kind 27235) HTTP-auth: the security-relevant URL and method live in
    // the event tags, not the (empty) content, so surface them so the user can see
    // exactly which request they are authorizing before approving.
    val sanitizedHttpUrl = remember(httpAuthUrl) { httpAuthUrl?.let { sanitizeDisplayContent(it) } }
    val sanitizedHttpMethod = remember(httpAuthMethod) { httpAuthMethod?.let { sanitizeDisplayContent(it) } }
    val sanitizedAppName = remember(appName) { sanitizeDisplayContent(appName) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        AppAvatar(
            key = appPubkey,
            name = sanitizedAppName,
            size = 56.dp
        )

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = if (isConnectRequest) stringResource(R.string.connections_nip46_title_connect) else stringResource(R.string.connections_nip46_title_request),
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = stringResource(R.string.connections_nip46_from, sanitizedAppName),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        if (isConnectRequest) {
            Spacer(modifier = Modifier.height(12.dp))
            Surface(
                color = MaterialTheme.colorScheme.tertiaryContainer,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = stringResource(R.string.connections_nip46_connect_description),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onTertiaryContainer,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f, fill = false)
        ) {
            Column(
                modifier = Modifier
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Nip46DetailRow(stringResource(R.string.connections_nip46_method), formatNip46Method(method))

                if (eventKind != null) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Nip46DetailRow(stringResource(R.string.connections_nip46_event_kind), EventKind.displayName(context, eventKind))
                }

                if (!sanitizedHttpUrl.isNullOrBlank() || !sanitizedHttpMethod.isNullOrBlank()) {
                    val unspecified = stringResource(R.string.connections_nip46_http_unspecified)
                    Spacer(modifier = Modifier.height(12.dp))
                    Nip46DetailRow(
                        stringResource(R.string.connections_nip46_http_url),
                        sanitizedHttpUrl?.takeIf { it.isNotBlank() } ?: unspecified
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Nip46DetailRow(
                        stringResource(R.string.connections_nip46_http_method),
                        sanitizedHttpMethod?.takeIf { it.isNotBlank() } ?: unspecified
                    )
                }

                if (!sanitizedContent.isNullOrBlank()) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = stringResource(R.string.connections_nip46_content),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = sanitizedContent,
                        style = MaterialTheme.typography.bodyMedium,
                        maxLines = 10,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))
                CopyableValue(
                    label = stringResource(R.string.connections_nip46_app_public_key),
                    value = appPubkey,
                    sensitive = false,
                    displayValue = formatPubkeyDisplay(appPubkey),
                    mono = true
                )
            }
        }

        if (!isConnectRequest) {
            Spacer(modifier = Modifier.height(16.dp))
            PermissionDurationSelector(
                label = stringResource(R.string.connections_nip46_remember_decision),
                selectedDuration = selectedDuration,
                expanded = durationDropdownExpanded,
                onExpandedChange = { durationDropdownExpanded = it },
                onDurationSelected = { selectedDuration = it }
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        if (isLoading) {
            CircularProgressIndicator()
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                OutlinedButton(
                    onClick = onReject,
                    modifier = Modifier.weight(1f)
                ) {
                    Text(stringResource(R.string.connections_nip46_reject))
                }
                Button(
                    onClick = {
                        isLoading = true
                        onApprove(selectedDuration) { success ->
                            if (!success) {
                                isLoading = false
                            }
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Text(if (isConnectRequest) stringResource(R.string.connections_nip46_authorize) else stringResource(R.string.connections_nip46_approve))
                }
            }
        }
    }
}
