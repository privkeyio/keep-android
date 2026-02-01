package io.privkey.keep.nip55

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.material3.MenuAnchorType
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import org.json.JSONArray
import org.json.JSONObject

internal fun Nip55RequestType.displayName(): String = when (this) {
    Nip55RequestType.GET_PUBLIC_KEY -> "Get Public Key"
    Nip55RequestType.SIGN_EVENT -> "Sign Event"
    Nip55RequestType.NIP44_ENCRYPT -> "Encrypt (NIP-44)"
    Nip55RequestType.NIP44_DECRYPT -> "Decrypt (NIP-44)"
    Nip55RequestType.NIP04_ENCRYPT -> "Encrypt (NIP-04)"
    Nip55RequestType.NIP04_DECRYPT -> "Decrypt (NIP-04)"
    Nip55RequestType.DECRYPT_ZAP_EVENT -> "Decrypt Zap Event"
}

internal fun Nip55RequestType.headerTitle(): String = when (this) {
    Nip55RequestType.GET_PUBLIC_KEY -> "Public Key Request"
    Nip55RequestType.SIGN_EVENT -> "Signing Request"
    Nip55RequestType.NIP44_ENCRYPT, Nip55RequestType.NIP04_ENCRYPT -> "Encryption Request"
    Nip55RequestType.NIP44_DECRYPT, Nip55RequestType.NIP04_DECRYPT -> "Decryption Request"
    Nip55RequestType.DECRYPT_ZAP_EVENT -> "Zap Decryption Request"
}

internal fun parseEventKind(content: String): Int? = runCatching {
    JSONObject(content).optInt("kind", -1).takeIf { it in 0..65535 }
}.getOrNull()

internal fun Nip55Request.eventKind(): Int? =
    if (requestType == Nip55RequestType.SIGN_EVENT) parseEventKind(content) else null

internal data class EventPreview(
    val kind: Int,
    val content: String,
    val pTags: List<String>,
    val eTags: List<String>,
    val tTags: List<String>,
    val recipientPubkey: String?
)

private val HEX_64_REGEX = Regex("^[0-9a-fA-F]{64}$")
private const val MAX_TAG_COUNT = 500
private const val MAX_TAG_VALUE_LENGTH = 1024
private const val MAX_CONTENT_LENGTH = 10_000

private fun isValidHex64(value: String): Boolean = HEX_64_REGEX.matches(value)

private fun sanitizeTTag(value: String): String =
    value.filterNot { it.isISOControl() || it in '\u2000'..'\u200F' || it in '\u2028'..'\u202F' || it in '\uFFF0'..'\uFFFF' }

internal fun parseEventPreview(eventJson: String): EventPreview? = runCatching {
    val json = JSONObject(eventJson)
    val kind = json.optInt("kind", -1).takeIf { it in 0..65535 } ?: return@runCatching null
    val tagsArray = json.optJSONArray("tags") ?: JSONArray()

    val pTags = mutableListOf<String>()
    val eTags = mutableListOf<String>()
    val tTags = mutableListOf<String>()

    val tagCount = minOf(tagsArray.length(), MAX_TAG_COUNT)
    for (i in 0 until tagCount) {
        val tag = tagsArray.optJSONArray(i) ?: continue
        if (tag.length() < 2) continue
        val tagValue = tag.optString(1).take(MAX_TAG_VALUE_LENGTH)
        when (tag.optString(0)) {
            "p" -> if (isValidHex64(tagValue)) pTags.add(tagValue)
            "e" -> if (isValidHex64(tagValue)) eTags.add(tagValue)
            "t" -> sanitizeTTag(tagValue).takeIf { it.isNotEmpty() }?.let { tTags.add(it) }
        }
    }

    EventPreview(
        kind = kind,
        content = json.optString("content", "").take(MAX_CONTENT_LENGTH),
        pTags = pTags,
        eTags = eTags,
        tTags = tTags,
        recipientPubkey = pTags.firstOrNull()
    )
}.getOrNull()

private fun formatPubkey(pubkey: String): String =
    if (pubkey.length > 24) "${pubkey.take(12)}...${pubkey.takeLast(8)}" else pubkey

private fun pluralize(count: Int, singular: String, plural: String): String =
    if (count == 1) "1 $singular" else "$count $plural"

@Composable
fun ApprovalScreen(
    request: Nip55Request,
    callerPackage: String?,
    callerVerified: Boolean,
    onApprove: (PermissionDuration) -> Unit,
    onReject: (PermissionDuration) -> Unit
) {
    var isLoading by remember { mutableStateOf(false) }
    val canRememberChoice = callerVerified && callerPackage != null
    var selectedDuration by remember { mutableStateOf(PermissionDuration.JUST_THIS_TIME) }
    var durationDropdownExpanded by remember { mutableStateOf(false) }
    val eventPreview = remember(request) {
        if (request.requestType == Nip55RequestType.SIGN_EVENT) parseEventPreview(request.content) else null
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = request.requestType.headerTitle(),
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        CallerLabel(callerPackage, callerVerified)

        if (!callerVerified) {
            Spacer(modifier = Modifier.height(8.dp))
            UnverifiedCallerWarning()
        }

        Spacer(modifier = Modifier.height(16.dp))

        RequestDetailsCard(request, eventPreview)

        Spacer(modifier = Modifier.height(16.dp))

        if (canRememberChoice) {
            DurationSelector(
                selectedDuration = selectedDuration,
                expanded = durationDropdownExpanded,
                onExpandedChange = { durationDropdownExpanded = it },
                onDurationSelected = { selectedDuration = it },
                isSensitiveKind = eventPreview?.let { isSensitiveKind(it.kind) } == true
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        val effectiveDuration = if (canRememberChoice) selectedDuration else PermissionDuration.JUST_THIS_TIME

        if (isLoading) {
            CircularProgressIndicator()
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                OutlinedButton(
                    onClick = { onReject(effectiveDuration) },
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Reject")
                }
                Button(
                    onClick = {
                        isLoading = true
                        onApprove(effectiveDuration)
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Approve")
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DurationSelector(
    selectedDuration: PermissionDuration,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    onDurationSelected: (PermissionDuration) -> Unit,
    isSensitiveKind: Boolean = false
) {
    val availableDurations = if (isSensitiveKind) {
        PermissionDuration.entries.filter { it != PermissionDuration.FOREVER }
    } else {
        PermissionDuration.entries
    }

    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = "Remember this choice",
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
                    .menuAnchor(MenuAnchorType.PrimaryNotEditable)
            )
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { onExpandedChange(false) }
            ) {
                availableDurations.forEach { duration ->
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
private fun CallerLabel(callerPackage: String?, callerVerified: Boolean) {
    val displayText = if (callerPackage != null) "from $callerPackage" else "from unknown app"
    val isTrusted = callerPackage != null && callerVerified
    val textColor = if (isTrusted) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error

    Text(
        text = displayText,
        style = MaterialTheme.typography.bodySmall,
        color = textColor
    )
}

@Composable
private fun UnverifiedCallerWarning() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Text(
            text = "Warning: Unable to verify the requesting app. Only approve if you initiated this action.",
            modifier = Modifier.padding(12.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onErrorContainer
        )
    }
}

@Composable
private fun ColumnScope.RequestDetailsCard(request: Nip55Request, eventPreview: EventPreview?) {
    val scrollState = rememberScrollState()

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .weight(1f, fill = false)
    ) {
        Column(
            modifier = Modifier
                .padding(16.dp)
                .verticalScroll(scrollState)
        ) {
            DetailRow("Type", request.requestType.displayName())

            if (eventPreview != null) {
                EventPreviewSection(eventPreview)
            } else if (request.content.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                ExpandableContentSection(request.content)
            }

            request.pubkey?.let { pk ->
                Spacer(modifier = Modifier.height(12.dp))
                DetailRow("Recipient", formatPubkey(pk), MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun EventPreviewSection(preview: EventPreview) {
    Spacer(modifier = Modifier.height(12.dp))
    DetailRow("Event Kind", EventKind.displayName(preview.kind))

    sensitiveKindWarning(preview.kind)?.let { warning ->
        Spacer(modifier = Modifier.height(8.dp))
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer
            )
        ) {
            Text(
                text = warning,
                modifier = Modifier.padding(8.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
        }
    }

    if (preview.content.isNotEmpty()) {
        Spacer(modifier = Modifier.height(12.dp))
        ExpandableContentSection(preview.content)
    }

    if (preview.recipientPubkey != null) {
        Spacer(modifier = Modifier.height(12.dp))
        DetailRow("Recipient", formatPubkey(preview.recipientPubkey), MaterialTheme.typography.bodyMedium)
    }

    val otherPubkeys = preview.pTags.drop(1)
    if (preview.eTags.isNotEmpty() || otherPubkeys.isNotEmpty() || preview.tTags.isNotEmpty()) {
        Spacer(modifier = Modifier.height(12.dp))
        TagsSummarySection(
            eTags = preview.eTags,
            otherPubkeys = otherPubkeys,
            tTags = preview.tTags
        )
    }
}

@Composable
private fun ExpandableContentSection(content: String, maxLength: Int = 200) {
    var expanded by remember { mutableStateOf(false) }
    val needsTruncation = content.length > maxLength
    val displayText = if (expanded || !needsTruncation) content else "${content.take(maxLength)}..."

    Text(
        text = "Content",
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Spacer(modifier = Modifier.height(4.dp))
    Text(
        text = displayText,
        style = MaterialTheme.typography.bodyMedium,
        maxLines = if (expanded) Int.MAX_VALUE else 5,
        overflow = TextOverflow.Ellipsis
    )
    if (needsTruncation) {
        TextButton(
            onClick = { expanded = !expanded },
            contentPadding = PaddingValues(0.dp),
            modifier = Modifier.height(32.dp)
        ) {
            Text(
                text = if (expanded) "Show less" else "Show more",
                style = MaterialTheme.typography.labelMedium
            )
        }
    }
}

@Composable
private fun TagsSummarySection(
    eTags: List<String>,
    otherPubkeys: List<String>,
    tTags: List<String>
) {
    Text(
        text = "References",
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Spacer(modifier = Modifier.height(4.dp))

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        if (eTags.isNotEmpty()) {
            TagSummaryRow("Events:", pluralize(eTags.size, "event", "events"))
        }

        if (otherPubkeys.isNotEmpty()) {
            TagSummaryRow("Mentions:", pluralize(otherPubkeys.size, "pubkey", "pubkeys"))
        }

        if (tTags.isNotEmpty()) {
            val topicsPreview = tTags.take(3).joinToString(", ") { "#$it" }
            val suffix = if (tTags.size > 3) " +${tTags.size - 3} more" else ""
            TagSummaryRow("Topics:", "$topicsPreview$suffix")
        }
    }
}

@Composable
private fun TagSummaryRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun DetailRow(
    label: String,
    value: String,
    valueStyle: TextStyle = MaterialTheme.typography.bodyLarge
) {
    Text(
        text = label,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Text(text = value, style = valueStyle)
}
