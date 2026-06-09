package io.privkey.keep.nip46

import io.privkey.keep.ui.components.KeepCard
import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import io.privkey.keep.MAX_BUNKER_RELAYS
import io.privkey.keep.QrCodeDisplay
import io.privkey.keep.R
import io.privkey.keep.RELAY_URL_REGEX
import io.privkey.keep.copySensitiveText
import io.privkey.keep.isInternalHost
import io.privkey.keep.setSecureScreen
import io.privkey.keep.uniffi.BunkerConfigInfo
import io.privkey.keep.uniffi.BunkerStatus
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.RelayConfigInfo
import io.privkey.keep.uniffi.truncateStr

private enum class RelayValidationError {
    TOO_LONG, INVALID, MAX_REACHED, DUPLICATE
}

private fun validateRelayUrl(url: String, existingRelays: List<String>): RelayValidationError? = when {
    url.length > 256 -> RelayValidationError.TOO_LONG
    !url.matches(RELAY_URL_REGEX) -> RelayValidationError.INVALID
    existingRelays.size >= MAX_BUNKER_RELAYS -> RelayValidationError.MAX_REACHED
    existingRelays.contains(url) -> RelayValidationError.DUPLICATE
    else -> null
}

private fun parseBunkerUrlRelays(input: String): List<String>? {
    if (!input.startsWith("bunker://")) return null
    val uri = runCatching { java.net.URI(input) }.getOrNull() ?: return null
    val query = uri.rawQuery ?: return null
    return query.split("&")
        .filter { it.startsWith("relay=") }
        .mapNotNull { param ->
            runCatching {
                java.net.URLDecoder.decode(param.removePrefix("relay="), Charsets.UTF_8)
            }.getOrNull()
        }
        .filter { it.startsWith("wss://") }
        .distinct()
        .ifEmpty { null }
}

private fun normalizeRelayUrl(input: String): String {
    val stripped = input
        .removePrefix("https://")
        .removePrefix("http://")
        .removePrefix("ws://")
    return if (stripped.startsWith("wss://")) stripped else "wss://$stripped"
}

private sealed class BunkerAddError(val exception: Exception) {
    object MaxReached : BunkerAddError(Exception("max"))
    object AlreadyAdded : BunkerAddError(Exception("added"))
    object PrivateOnly : BunkerAddError(Exception("private"))
    object NoValid : BunkerAddError(Exception("none"))
}

private suspend fun addBunkerRelays(
    bunkerRelays: List<String>,
    existingRelays: List<String>,
): Result<List<String>> {
    val validRelays = bunkerRelays.filter { validateRelayUrl(it, existingRelays) == null }
    val safeRelays = withContext(Dispatchers.IO) {
        validRelays.filter { !isInternalHost(it) }
    }
    val remaining = MAX_BUNKER_RELAYS - existingRelays.size

    if (remaining <= 0) return Result.failure(BunkerAddError.MaxReached.exception)

    val toAdd = safeRelays.take(remaining)
    if (toAdd.isEmpty()) {
        val err: BunkerAddError = when {
            bunkerRelays.all { existingRelays.contains(it) } -> BunkerAddError.AlreadyAdded
            validRelays.isNotEmpty() && safeRelays.isEmpty() -> BunkerAddError.PrivateOnly
            else -> BunkerAddError.NoValid
        }
        return Result.failure(err.exception)
    }

    return Result.success(toAdd)
}

@Composable
fun BunkerScreen(
    keepMobile: KeepMobile,
    bunkerUrl: String?,
    bunkerStatus: BunkerStatus,
    onToggleBunker: (Boolean) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var relays by remember { mutableStateOf<List<String>>(emptyList()) }
    var authorizedClients by remember { mutableStateOf<Set<String>>(emptySet()) }
    var showAddDialog by remember { mutableStateOf(false) }
    var showRevokeAllDialog by remember { mutableStateOf(false) }
    val isEnabled = bunkerStatus == BunkerStatus.RUNNING || bunkerStatus == BunkerStatus.STARTING

    val toastBunkerUrlCopied = stringResource(R.string.connections_bunker_url_copied)
    val toastAddRelayFirst = stringResource(R.string.connections_bunker_toast_add_relay_first)
    val toastSaveBunkerFailed = stringResource(R.string.connections_bunker_toast_save_bunker_failed)
    val toastSaveRelayFailed = stringResource(R.string.connections_bunker_toast_save_relay_failed)
    val toastClientRevoked = stringResource(R.string.connections_bunker_toast_client_revoked)
    val toastRevokeFailed = stringResource(R.string.connections_bunker_toast_revoke_failed)
    val toastAllClientsRevoked = stringResource(R.string.connections_bunker_toast_all_clients_revoked)
    val toastRevokeAllFailed = stringResource(R.string.connections_bunker_toast_revoke_all_failed)

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            runCatching { keepMobile.getBunkerConfig() }.onSuccess { config ->
                withContext(Dispatchers.Main) { authorizedClients = config.authorizedClients.toSet() }
            }
            runCatching { keepMobile.getRelayConfig(null) }.onSuccess { config ->
                withContext(Dispatchers.Main) { relays = config.bunkerRelays }
            }
        }
    }

    DisposableEffect(Unit) {
        setSecureScreen(context, true)
        onDispose {
            setSecureScreen(context, false)
        }
    }

    fun saveBunkerRelays(updated: List<String>) {
        scope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    val config = keepMobile.getRelayConfig(null)
                    keepMobile.saveRelayConfig(null, RelayConfigInfo(config.frostRelays, config.profileRelays, updated))
                }
            }.onFailure {
                Toast.makeText(context, toastSaveRelayFailed, Toast.LENGTH_SHORT).show()
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = stringResource(R.string.connections_bunker_screen_title),
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        StatusBadge(bunkerStatus)

        Spacer(modifier = Modifier.height(16.dp))

        if (bunkerUrl != null && bunkerStatus == BunkerStatus.RUNNING) {
            QrCodeDisplay(
                data = bunkerUrl,
                label = stringResource(R.string.connections_bunker_qr_label),
                onCopied = {
                    Toast.makeText(context, toastBunkerUrlCopied, Toast.LENGTH_SHORT).show()
                }
            )

            Spacer(modifier = Modifier.height(8.dp))

            OutlinedButton(
                onClick = {
                    copySensitiveText(context, bunkerUrl)
                    Toast.makeText(context, toastBunkerUrlCopied, Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.connections_bunker_copy_button))
            }

            Spacer(modifier = Modifier.height(16.dp))
        }

        BunkerToggleCard(
            enabled = isEnabled,
            canEnable = relays.isNotEmpty(),
            onToggle = { enabled ->
                if (enabled && relays.isEmpty()) {
                    Toast.makeText(context, toastAddRelayFirst, Toast.LENGTH_SHORT).show()
                    return@BunkerToggleCard
                }
                scope.launch {
                    runCatching {
                        withContext(Dispatchers.IO) {
                            BunkerConfigStore.update(keepMobile) { current ->
                                BunkerConfigInfo(enabled, current.authorizedClients)
                            }
                        }
                    }.onSuccess {
                        onToggleBunker(enabled)
                    }.onFailure {
                        Toast.makeText(context, toastSaveBunkerFailed, Toast.LENGTH_SHORT).show()
                    }
                }
            }
        )

        Spacer(modifier = Modifier.height(16.dp))

        BunkerRelaysCard(
            relays = relays,
            isEnabled = isEnabled,
            onAddClick = { showAddDialog = true },
            onRemove = { relay ->
                val updated = relays - relay
                relays = updated
                saveBunkerRelays(updated)
            }
        )

        Spacer(modifier = Modifier.height(16.dp))

        AuthorizedClientsCard(
            clients = authorizedClients,
            onRevoke = { pubkey ->
                scope.launch {
                    runCatching {
                        withContext(Dispatchers.IO) {
                            Nip46ClientStore.addToDenylist(context, pubkey)
                            BunkerConfigStore.update(keepMobile) { config ->
                                BunkerConfigInfo(config.enabled, config.authorizedClients.filter { it.lowercase() != pubkey.lowercase() })
                            }
                        }
                    }.onSuccess { saved ->
                        BunkerService.forgetPendingAuth(pubkey)
                        authorizedClients = saved.authorizedClients.toSet()
                        Toast.makeText(context, toastClientRevoked, Toast.LENGTH_SHORT).show()
                    }.onFailure {
                        Toast.makeText(context, toastRevokeFailed, Toast.LENGTH_SHORT).show()
                    }
                }
            },
            onRevokeAll = { showRevokeAllDialog = true }
        )

        Spacer(modifier = Modifier.height(24.dp))

        TextButton(
            onClick = onDismiss,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.back))
        }
    }

    if (showAddDialog) {
        AddBunkerRelayDialog(
            relays = relays,
            onRelaysUpdated = { updated ->
                relays = updated
                saveBunkerRelays(updated)
            },
            onDismiss = { showAddDialog = false }
        )
    }

    if (showRevokeAllDialog) {
        RevokeAllClientsDialog(
            onConfirm = {
                scope.launch {
                    val revoked = authorizedClients
                    runCatching {
                        withContext(Dispatchers.IO) {
                            Nip46ClientStore.addAllToDenylist(context, revoked)
                            BunkerConfigStore.update(keepMobile) { config ->
                                BunkerConfigInfo(config.enabled, emptyList())
                            }
                        }
                    }.onSuccess {
                        revoked.forEach { BunkerService.forgetPendingAuth(it) }
                        authorizedClients = emptySet()
                        Toast.makeText(context, toastAllClientsRevoked, Toast.LENGTH_SHORT).show()
                    }.onFailure {
                        Toast.makeText(context, toastRevokeAllFailed, Toast.LENGTH_SHORT).show()
                    }
                }
            },
            onDismiss = { showRevokeAllDialog = false }
        )
    }
}

@Composable
private fun AddBunkerRelayDialog(
    relays: List<String>,
    onRelaysUpdated: (List<String>) -> Unit,
    onDismiss: () -> Unit
) {
    val scope = rememberCoroutineScope()
    var newRelayUrl by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var isAdding by remember { mutableStateOf(false) }

    val errTooLong = stringResource(R.string.connections_bunker_relay_error_too_long)
    val errInvalid = stringResource(R.string.connections_bunker_relay_error_invalid)
    val errMax = stringResource(R.string.connections_bunker_relay_error_max)
    val errDuplicate = stringResource(R.string.connections_bunker_relay_error_duplicate)
    val errAllDuplicates = stringResource(R.string.connections_bunker_relay_error_all_duplicates)
    val errPrivate = stringResource(R.string.connections_bunker_relay_error_private)
    val errNoValid = stringResource(R.string.connections_bunker_relay_error_no_valid)
    val errNoRelaysInUrl = stringResource(R.string.connections_bunker_add_dialog_no_relays_in_url)
    val errInternalHost = stringResource(R.string.connections_bunker_add_dialog_internal_host)

    fun validationErrorMessage(e: RelayValidationError): String = when (e) {
        RelayValidationError.TOO_LONG -> errTooLong
        RelayValidationError.INVALID -> errInvalid
        RelayValidationError.MAX_REACHED -> errMax
        RelayValidationError.DUPLICATE -> errDuplicate
    }

    fun addErrorMessage(throwable: Throwable): String = when (throwable.message) {
        "max" -> errMax
        "added" -> errAllDuplicates
        "private" -> errPrivate
        else -> errNoValid
    }

    fun dismissDialog() {
        newRelayUrl = ""
        error = null
        onDismiss()
    }

    AlertDialog(
        onDismissRequest = ::dismissDialog,
        title = { Text(stringResource(R.string.connections_bunker_add_dialog_title)) },
        text = {
            Column {
                OutlinedTextField(
                    value = newRelayUrl,
                    onValueChange = {
                        newRelayUrl = it
                        error = null
                    },
                    label = { Text(stringResource(R.string.connections_bunker_add_dialog_label)) },
                    placeholder = { Text(stringResource(R.string.connections_bunker_add_dialog_placeholder)) },
                    singleLine = true,
                    isError = error != null
                )
                error?.let {
                    Text(
                        it,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    if (isAdding) return@TextButton
                    val trimmed = newRelayUrl.trim()
                    val bunkerRelays = parseBunkerUrlRelays(trimmed)

                    when {
                        bunkerRelays != null -> {
                            isAdding = true
                            scope.launch {
                                addBunkerRelays(bunkerRelays, relays).fold(
                                    onSuccess = { toAdd ->
                                        onRelaysUpdated(relays + toAdd)
                                        dismissDialog()
                                    },
                                    onFailure = { error = addErrorMessage(it) }
                                )
                                isAdding = false
                            }
                        }
                        trimmed.startsWith("bunker://") ->
                            error = errNoRelaysInUrl
                        else -> {
                            val url = normalizeRelayUrl(trimmed)
                            val validationError = validateRelayUrl(url, relays)
                            if (validationError != null) {
                                error = validationErrorMessage(validationError)
                            } else {
                                isAdding = true
                                scope.launch {
                                    val isInternal = withContext(Dispatchers.IO) {
                                        isInternalHost(url)
                                    }
                                    if (isInternal) {
                                        error = errInternalHost
                                    } else {
                                        onRelaysUpdated(relays + url)
                                        dismissDialog()
                                    }
                                    isAdding = false
                                }
                            }
                        }
                    }
                },
                enabled = !isAdding
            ) {
                if (isAdding) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.connections_bunker_add_dialog_add))
                }
            }
        },
        dismissButton = {
            TextButton(onClick = ::dismissDialog) {
                Text(stringResource(R.string.connections_bunker_add_dialog_cancel))
            }
        }
    )
}

@Composable
private fun RevokeAllClientsDialog(
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.connections_bunker_revoke_all_title)) },
        text = {
            Text(stringResource(R.string.connections_bunker_revoke_all_text))
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onConfirm()
                    onDismiss()
                },
                colors = ButtonDefaults.textButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                )
            ) {
                Text(stringResource(R.string.connections_bunker_revoke_all_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.connections_bunker_revoke_all_cancel))
            }
        }
    )
}

@Composable
private fun StatusBadge(status: BunkerStatus) {
    val running = stringResource(R.string.connections_bunker_status_running)
    val starting = stringResource(R.string.connections_bunker_status_starting)
    val errText = stringResource(R.string.connections_bunker_status_error)
    val stopped = stringResource(R.string.connections_bunker_status_stopped)
    val (statusText, statusColor) = when (status) {
        BunkerStatus.RUNNING -> running to MaterialTheme.colorScheme.primary
        BunkerStatus.STARTING -> starting to MaterialTheme.colorScheme.secondary
        BunkerStatus.ERROR -> errText to MaterialTheme.colorScheme.error
        BunkerStatus.STOPPED -> stopped to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Text(
        text = statusText,
        style = MaterialTheme.typography.labelLarge,
        color = statusColor
    )
}

@Composable
private fun BunkerToggleCard(
    enabled: Boolean,
    canEnable: Boolean,
    onToggle: (Boolean) -> Unit
) {
    KeepCard(contentPadding = PaddingValues(0.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.connections_bunker_toggle_title), style = MaterialTheme.typography.titleMedium)
                Text(
                    stringResource(R.string.connections_bunker_toggle_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(
                checked = enabled,
                onCheckedChange = onToggle,
                enabled = canEnable || enabled
            )
        }
    }
}

@Composable
private fun BunkerRelaysCard(
    relays: List<String>,
    isEnabled: Boolean,
    onAddClick: () -> Unit,
    onRemove: (String) -> Unit
) {
    KeepCard(contentPadding = PaddingValues(0.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(stringResource(R.string.connections_bunker_relays_title), style = MaterialTheme.typography.titleMedium)
                IconButton(onClick = onAddClick, enabled = !isEnabled) {
                    Icon(Icons.Default.Add, contentDescription = stringResource(R.string.connections_bunker_relays_add_cd))
                }
            }
            if (relays.isEmpty()) {
                Text(
                    stringResource(R.string.connections_bunker_relays_none),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                relays.forEach { relay ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            relay.removePrefix("wss://"),
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodyMedium
                        )
                        IconButton(
                            onClick = { onRemove(relay) },
                            modifier = Modifier.size(24.dp),
                            enabled = !isEnabled
                        ) {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = stringResource(R.string.connections_bunker_relays_remove_cd),
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AuthorizedClientsCard(
    clients: Set<String>,
    onRevoke: (String) -> Unit,
    onRevokeAll: () -> Unit
) {
    KeepCard(contentPadding = PaddingValues(0.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(stringResource(R.string.connections_bunker_clients_title), style = MaterialTheme.typography.titleMedium)
                if (clients.isNotEmpty()) {
                    TextButton(
                        onClick = onRevokeAll,
                        colors = ButtonDefaults.textButtonColors(
                            contentColor = MaterialTheme.colorScheme.error
                        )
                    ) {
                        Text(stringResource(R.string.connections_bunker_clients_revoke_all), style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                stringResource(R.string.connections_bunker_clients_description),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            if (clients.isEmpty()) {
                Text(
                    stringResource(R.string.connections_bunker_clients_none),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                clients.forEach { pubkey ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            truncateStr(pubkey, 8u, 6u),
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodySmall
                        )
                        IconButton(
                            onClick = { onRevoke(pubkey) },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = stringResource(R.string.connections_bunker_client_revoke_cd),
                                modifier = Modifier.size(16.dp),
                                tint = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            }
        }
    }
}
