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
    onDismiss: () -> Unit
) {
    var hosts by remember { mutableStateOf<List<String>>(emptyList()) }
    var readFailed by remember { mutableStateOf(false) }
    var input by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }
    var confirmReset by remember { mutableStateOf(false) }
    var resetFailed by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    suspend fun reload() {
        // A fault keeps whatever rows were already read instead of replacing them
        // with an empty list, and raises [readFailed], which withholds the "nothing
        // is whitelisted" line below. That line is a claim about what the gate will
        // enforce, and on a cold open the list is empty because nothing has been
        // read yet, so making it for a list that failed to read would state the
        // opposite of the truth. Saying which of the two it is needs a string this
        // screen does not have yet. Previously this also raised out of the
        // coroutine on a name-resolution fault and took the screen down.
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
            // rather than sitting above an input whose every attempt would fail with
            // the error a bad host gets.
            if (readFailed) {
                Text(
                    text = stringResource(R.string.connections_nip55_relay_auth_whitelist_unreadable),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error
                )
                if (resetFailed) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = stringResource(R.string.connections_nip55_relay_auth_whitelist_reset_failed),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error
                    )
                }
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
                    onValueChange = { input = it; error = false },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    isError = error,
                    label = { Text(stringResource(R.string.connections_nip55_relay_auth_whitelist_add_label)) },
                    placeholder = { Text(stringResource(R.string.connections_nip55_relay_auth_whitelist_placeholder)) }
                )
                Button(
                    enabled = input.isNotBlank(),
                    onClick = {
                        scope.launch {
                            val added = withContext(Dispatchers.IO) { store.add(input) }
                            if (added == null) {
                                error = true
                            } else {
                                input = ""
                                reload()
                            }
                        }
                    }
                ) {
                    Text(stringResource(R.string.connections_nip55_relay_auth_whitelist_add))
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            if (hosts.isEmpty() && !readFailed) {
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

    if (confirmReset) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            title = { Text(stringResource(R.string.connections_nip55_relay_auth_whitelist_reset_title)) },
            text = { Text(stringResource(R.string.connections_nip55_relay_auth_whitelist_reset_message)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmReset = false
                    scope.launch {
                        // The store answers whether the delete was certified, and an
                        // uncertified one leaves the list on disk and the gate still
                        // rejecting. Reported rather than assumed, so the screen cannot
                        // tell the person the whitelist is reset while it is not.
                        resetFailed = !withContext(Dispatchers.IO) { store.clear() }
                        reload()
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
