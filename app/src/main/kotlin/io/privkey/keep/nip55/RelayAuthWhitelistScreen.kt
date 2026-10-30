package io.privkey.keep.nip55

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.privkey.keep.R
import io.privkey.keep.storage.PrefRead
import io.privkey.keep.storage.RelayAuthWhitelistStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RelayAuthWhitelistScreen(
    store: RelayAuthWhitelistStore,
    onDismiss: () -> Unit,
    /**
     * Runs the reset behind a verified auth factor.
     *
     * A reset moves this gate from rejecting every relay to deferring to per-app
     * grants, and a grant can auto-approve a kind 22242 request in the background with
     * nobody present. That is a security downgrade, and the app gates those on a live
     * auth factor rather than on a dialog alone, the same way clearing a certificate
     * pin or weakening the app lock is gated.
     */
    gateReset: (action: suspend () -> Unit) -> Unit
) {
    var hosts by remember { mutableStateOf<List<String>>(emptyList()) }
    var readFailed by remember { mutableStateOf(false) }
    var input by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<Int?>(null) }
    var confirmReset by remember { mutableStateOf(false) }
    var resetFailed by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    suspend fun reload() {
        // A fault keeps whatever rows were already read instead of replacing them
        // with an empty list, and raises [readFailed], which replaces the list and
        // the input with the fault below. Reporting "nothing is whitelisted" there
        // would be a claim about what the gate enforces, and on a cold open the list
        // is empty because nothing has been read yet, so for a list that failed to
        // read it states the opposite of the truth. This also used to raise out of
        // the coroutine on a name-resolution fault and take the screen down.
        val read = withContext(Dispatchers.IO) {
            runCatching { store.readHosts() }.getOrDefault(PrefRead.Unreadable)
        }
        if (read is PrefRead.Found) hosts = read.value
        readFailed = read !is PrefRead.Found
    }

    LaunchedEffect(Unit) { reload() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.connections_nip55_relay_auth_whitelist_title)) },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {
            Text(
                text = stringResource(R.string.connections_nip55_relay_auth_whitelist_description),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(16.dp))

            // Nothing below this is usable while the list cannot be read: add refuses
            // to write over a list it could not read, there are no rows to remove, and
            // the gate is rejecting every relay meanwhile. So the fault replaces them
            // rather than sitting above an input whose every attempt would fail.
            // Outside the fault block below, because a reset can fail and still leave
            // the next read succeeding: the delete is uncertified while the value is
            // gone from this instance's view. Nested under the fault, that outcome
            // would never be shown, and the screen would look recovered until a
            // restart brought the list back.
            if (resetFailed) {
                Text(
                    text = stringResource(R.string.connections_nip55_relay_auth_whitelist_reset_failed),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error
                )
                Spacer(modifier = Modifier.height(16.dp))
            }

            if (readFailed) {
                Text(
                    text = stringResource(R.string.connections_nip55_relay_auth_whitelist_unreadable),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error
                )
                Spacer(modifier = Modifier.height(16.dp))
                Button(onClick = { confirmReset = true }) {
                    Text(stringResource(R.string.connections_nip55_relay_auth_whitelist_reset))
                }
                return@Column
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it; error = null },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    isError = error != null,
                    supportingText = error?.let { { Text(stringResource(it)) } },
                    label = { Text(stringResource(R.string.connections_nip55_relay_auth_whitelist_add_label)) },
                    placeholder = { Text(stringResource(R.string.connections_nip55_relay_auth_whitelist_placeholder)) }
                )
                Button(
                    enabled = input.isNotBlank(),
                    onClick = {
                        scope.launch {
                            when (withContext(Dispatchers.IO) { store.add(input) }) {
                                is RelayAuthWhitelistStore.AddResult.Added -> {
                                    input = ""
                                    error = null
                                    reload()
                                }
                                RelayAuthWhitelistStore.AddResult.InvalidHost ->
                                    error = R.string.connections_nip55_relay_auth_whitelist_invalid_host
                                RelayAuthWhitelistStore.AddResult.Full ->
                                    error = R.string.connections_nip55_relay_auth_whitelist_full
                                RelayAuthWhitelistStore.AddResult.Unreadable -> {
                                    error = R.string.connections_nip55_relay_auth_whitelist_save_failed
                                    reload()
                                }
                                RelayAuthWhitelistStore.AddResult.NotSaved ->
                                    error = R.string.connections_nip55_relay_auth_whitelist_save_failed
                            }
                        }
                    }
                ) {
                    Text(stringResource(R.string.connections_nip55_relay_auth_whitelist_add))
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            if (hosts.isEmpty()) {
                Text(
                    text = stringResource(R.string.connections_nip55_relay_auth_whitelist_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(hosts) { host ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(start = 16.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = host,
                                    modifier = Modifier.weight(1f),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    style = MaterialTheme.typography.bodyMedium
                                )
                                IconButton(onClick = {
                                    scope.launch {
                                        withContext(Dispatchers.IO) { store.remove(host) }
                                        reload()
                                    }
                                }) {
                                    Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.connections_relays_remove_cd))
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Gated on the fault as well as on the request, so the destructive action stays
    // tied to the state that justifies it even if the read recovers while the dialog
    // is open.
    if (confirmReset && readFailed) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            title = { Text(stringResource(R.string.connections_nip55_relay_auth_whitelist_reset_title)) },
            text = { Text(stringResource(R.string.connections_nip55_relay_auth_whitelist_reset_message)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmReset = false
                    gateReset {
                        resetFailed = false
                        error = null
                        // Read again before destroying anything. The fault is latched
                        // from the last read, an Unreadable can be transient, and the
                        // gate is read per request rather than from this screen, so a
                        // list that has become readable again is live and configured.
                        // Confirming a fault that is over must not delete it.
                        val current = withContext(Dispatchers.IO) {
                            runCatching { store.readHosts() }.getOrDefault(PrefRead.Unreadable)
                        }
                        if (current is PrefRead.Found) {
                            hosts = current.value
                            readFailed = false
                        } else {
                            // The store answers whether the delete reached disk, and a
                            // false leaves the list there and the gate still rejecting.
                            // Reported rather than assumed, so the screen cannot tell
                            // the person the whitelist is reset while it is not.
                            resetFailed = !withContext(Dispatchers.IO) { store.clear() }
                            reload()
                        }
                    }
                }) {
                    Text(stringResource(R.string.connections_nip55_relay_auth_whitelist_reset_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmReset = false }) {
                    Text(stringResource(R.string.common_cancel))
                }
            }
        )
    }
}
