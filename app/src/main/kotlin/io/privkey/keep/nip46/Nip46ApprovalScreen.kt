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

/**
 * The HTTP-auth (NIP-98, kind 27235) detail rows for the approval prompt as
 * (label resource id, display value) pairs, or empty when the request carries no
 * HTTP-auth. Gated on presence ([hasHttpAuth]), not field content: the signer core
 * returns a present-but-empty httpAuth for a malformed 27235 (no `u` tag), and both
 * rows must still render with [unspecified] so the missing target is flagged, never
 * silently hidden.
 */
internal fun httpAuthRows(
    hasHttpAuth: Boolean,
    url: String?,
    method: String?,
    unspecified: String
): List<Pair<Int, String>> {
    if (!hasHttpAuth) return emptyList()
    return listOf(
        R.string.connections_nip46_http_url to (url?.takeIf { it.isNotBlank() } ?: unspecified),
        R.string.connections_nip46_http_method to (method?.takeIf { it.isNotBlank() } ?: unspecified)
    )
}

@Composable
fun Nip46ApprovalScreen(
    appPubkey: String,
    appName: String,
    method: String,
    eventKind: Int?,
    eventContent: String?,
    isConnectRequest: Boolean = false,
    hasHttpAuth: Boolean = false,
    httpAuthUrl: String? = null,
    httpAuthMethod: String? = null,
    onApprove: (duration: PermissionDuration, onComplete: (success: Boolean) -> Unit) -> Unit,
    onReject: (duration: PermissionDuration) -> Unit
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

                // Gate on PRESENCE, not field content: the signer core returns a
                // present-but-empty httpAuth for a malformed kind-27235 so the prompt
                // must flag the missing target ("Unspecified"), never hide it.
                httpAuthRows(hasHttpAuth, sanitizedHttpUrl, sanitizedHttpMethod, stringResource(R.string.connections_nip46_http_unspecified))
                    .forEach { (labelRes, value) ->
                        Spacer(modifier = Modifier.height(12.dp))
                        Nip46DetailRow(stringResource(labelRes), value, valueMaxLines = 4)
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
                    // The selector above is labelled "Remember this decision",
                    // and a refusal is a decision. Passing it here is the code
                    // honouring what the label already promises; before this the
                    // choice was silently discarded on this branch, so a user who
                    // picked a duration and refused was asked again immediately.
                    onClick = { onReject(selectedDuration) },
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
