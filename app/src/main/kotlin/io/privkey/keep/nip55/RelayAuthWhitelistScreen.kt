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
    var input by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    suspend fun reload() {
        hosts = withContext(Dispatchers.IO) { store.getHosts() }
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
                    placeholder = { Text("wss://relay.example.com") }
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
}
