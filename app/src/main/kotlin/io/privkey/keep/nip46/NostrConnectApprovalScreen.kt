package io.privkey.keep.nip46

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import io.privkey.keep.R
import io.privkey.keep.uniffi.NostrConnectInfo
import io.privkey.keep.uniffi.formatPubkeyDisplay
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

// The methods a user can withhold on a nostrconnect accept, mirroring keep-nip46 handler.rs
// parse_permission_string. The core grants sign_event for every kind even when the request
// names one, so the screen offers methods, not kinds, and it grants get_public_key with any of
// them, so that one is not offered. Once the core reports the grantable methods on
// NostrConnectInfo (privkeyio/keep follow-up), this port goes.
private val GRANTABLE_METHODS = listOf(
    "sign_event",
    "nip04_encrypt", "nip04_decrypt",
    "nip44_encrypt", "nip44_decrypt",
    "nip44v3_encrypt", "nip44v3_decrypt",
)

// The mobile bunker's connect grant (keep-mobile nip46.rs connect_grant) less get_public_key:
// what the core grants a request that names no permission.
private val CONNECT_GRANT_METHODS = listOf("sign_event")

// Rust's str::trim, which the core parses with: Kotlin's trim also drops U+001C..U+001F.
private fun isRustWhitespace(c: Char): Boolean =
    c in "\u0009\u000A\u000B\u000C\u000D\u0020\u0085\u00A0\u1680\u2028\u2029\u202F\u205F\u3000" || c in '\u2000'..'\u200A'

private fun String.rustTrim(): String = dropWhile(::isRustWhitespace).dropLastWhile(::isRustWhitespace)

/** Whether [perms] names no permission at all, which the core reads as asking for its connect grant. */
internal fun namesNoNostrconnectPerms(perms: String?): Boolean =
    perms == null || perms.split(',').none { it.rustTrim().isNotEmpty() }

/**
 * The methods the core would grant [perms] that the user can withhold, in a stable order: the
 * connect grant when it names nothing, and otherwise the methods it names that the core knows.
 * Only `sign_event` takes a `:kind` suffix; the core reads any other suffixed method as unknown.
 */
internal fun offeredNostrconnectMethods(perms: String?): List<String> {
    if (namesNoNostrconnectPerms(perms)) return CONNECT_GRANT_METHODS
    val asked = perms.orEmpty().split(',').map { part ->
        part.rustTrim().let { if (it.startsWith("sign_event:")) "sign_event" else it }
    }.toSet()
    return GRANTABLE_METHODS.filter { it in asked }
}

/**
 * The approval to hand the core: get_public_key plus what was kept, in offered order. Never
 * null, which the core reads as the request as asked, and never empty, which it reads as its
 * default grant. The core intersects it with what the request asked for, or with its connect
 * grant when it named nothing, so get_public_key alone withholds everything else.
 */
internal fun approvedNostrconnectPerms(offered: List<String>, kept: Set<String>): String =
    (listOf("get_public_key") + offered.filter { it in kept }).joinToString(",")

/**
 * A client's name fit to show, or null when it has no letter or digit to show (blank, only
 * marks, format characters or Hangul fillers), so the caller shows its own placeholder.
 * Invisible format characters (tag characters, the soft hyphen, U+180E and the rest of Cf) are
 * dropped for display only, so "Damus" followed by tag characters shows as "Damus".
 */
internal fun nostrconnectDisplayName(name: String?): String? {
    val visible = name?.withoutFormatCharacters() ?: return null
    if (!visible.hasVisibleCharacter()) return null
    // Checked again after cleaning, which can cut the name short of its first visible character.
    return stripInvisibleAndCap(visible).trim().takeIf { it.hasVisibleCharacter() }
}

private fun String.withoutFormatCharacters(): String = buildString {
    this@withoutFormatCharacters.codePoints().forEach { cp ->
        val hidden = cp in 0xE0000..0xE007F || cp == 0x00AD || cp == 0x180E ||
            Character.getType(cp) == Character.FORMAT.toInt()
        if (!hidden) appendCodePoint(cp)
    }
}

private fun String.hasVisibleCharacter(): Boolean =
    codePoints().anyMatch { cp -> Character.isLetterOrDigit(cp) && cp !in HANGUL_FILLERS }

private val HANGUL_FILLERS = setOf(0x115F, 0x1160, 0x3164, 0xFFA0)

private const val CONNECT_ARM_DELAY_MS = 500L

@Composable
fun NostrConnectApprovalScreen(
    info: NostrConnectInfo,
    onApprove: (approvedPerms: String, onComplete: (Boolean) -> Unit) -> Unit,
    onReject: () -> Unit
) {
    // What the core will grant, offered as it would grant it. A request naming no permission
    // gets the mobile connect grant, so its sign_event is offered too, checked as the core would
    // grant it. This mirrors the core's rules until it reports them (privkeyio/keep follow-up).
    val offered = remember(info) { offeredNostrconnectMethods(info.requestedPermissions) }
    val namesNothing = remember(info) { namesNoNostrconnectPerms(info.requestedPermissions) }
    var kept by remember(info) { mutableStateOf(offered.toSet()) }
    var isLoading by remember { mutableStateOf(false) }
    // Taps on Connect are ignored for a moment after every resume, as on the system permission
    // dialogs, so a tap meant for whatever was on screen before, or for a screen that covered
    // this one and just closed, cannot approve.
    var connectArmed by remember { mutableStateOf(false) }
    val armScope = rememberCoroutineScope()
    LifecycleResumeEffect(Unit) {
        val arming = armScope.launch {
            delay(CONNECT_ARM_DELAY_MS)
            connectArmed = true
        }
        onPauseOrDispose {
            arming.cancel()
            connectArmed = false
        }
    }
    val name = nostrconnectDisplayName(info.name) ?: stringResource(R.string.connections_nostrconnect_unknown_app)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = stringResource(R.string.connections_nostrconnect_title),
            style = MaterialTheme.typography.headlineMedium
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.connections_nostrconnect_from, name),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        // The key is what the app is; its name and website below are only what it claims.
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.connections_nostrconnect_client_pubkey),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = formatPubkeyDisplay(info.clientPubkey),
            style = MaterialTheme.typography.titleSmall,
            fontFamily = FontFamily.Monospace
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.connections_nostrconnect_unverified),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(12.dp))
        Surface(
            color = MaterialTheme.colorScheme.tertiaryContainer,
            shape = MaterialTheme.shapes.small,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = stringResource(R.string.connections_nostrconnect_description),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onTertiaryContainer,
                modifier = Modifier.padding(12.dp)
            )
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
                info.url?.let {
                    Nip46DetailRow(stringResource(R.string.connections_nostrconnect_website_claimed), it)
                    Spacer(modifier = Modifier.height(12.dp))
                }

                Text(
                    text = stringResource(R.string.connections_nostrconnect_relays),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                info.relays.forEach { relay ->
                    Text(text = relay.removePrefix("wss://"), style = MaterialTheme.typography.bodyMedium)
                }

                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.connections_nostrconnect_requested_permissions),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                val permissionsNote = when {
                    namesNothing -> R.string.connections_nostrconnect_default_permissions
                    offered.isEmpty() -> R.string.connections_nostrconnect_no_permissions
                    else -> null
                }
                permissionsNote?.let { Text(text = stringResource(it), style = MaterialTheme.typography.bodyMedium) }
                offered.forEach { method ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = method in kept,
                            enabled = !isLoading,
                            onCheckedChange = { checked -> kept = if (checked) kept + method else kept - method }
                        )
                        Text(text = formatNip46Method(method), style = MaterialTheme.typography.bodyMedium)
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.connections_nostrconnect_grant_scope),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        if (isLoading) {
            CircularProgressIndicator()
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                OutlinedButton(onClick = onReject, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.connections_nostrconnect_reject))
                }
                Button(
                    onClick = {
                        isLoading = true
                        onApprove(approvedNostrconnectPerms(offered, kept)) { success ->
                            if (!success) isLoading = false
                        }
                    },
                    enabled = connectArmed,
                    modifier = Modifier.weight(1f)
                ) {
                    Text(stringResource(R.string.connections_nostrconnect_connect))
                }
            }
        }
    }
}
