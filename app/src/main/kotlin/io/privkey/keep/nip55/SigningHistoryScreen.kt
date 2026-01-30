package io.privkey.keep.nip55

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

private const val PAGE_SIZE = 50

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SigningHistoryScreen(
    permissionStore: PermissionStore,
    onDismiss: () -> Unit
) {
    var logs by remember { mutableStateOf<List<Nip55AuditLog>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var isLoadingMore by remember { mutableStateOf(false) }
    var hasMore by remember { mutableStateOf(true) }
    var selectedApp by remember { mutableStateOf<String?>(null) }
    var availableApps by remember { mutableStateOf<List<String>>(emptyList()) }
    var appFilterExpanded by remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()
    val listState = rememberLazyListState()

    var loadError by remember { mutableStateOf<String?>(null) }

    fun loadLogs(reset: Boolean = false) {
        coroutineScope.launch {
            try {
                if (reset) isLoading = true else isLoadingMore = true
                val offset = if (reset) 0 else logs.size

                val newLogs = permissionStore.getAuditLogPage(
                    limit = PAGE_SIZE,
                    offset = offset,
                    callerPackage = selectedApp
                )

                logs = if (reset) newLogs else logs + newLogs
                hasMore = newLogs.size == PAGE_SIZE
                loadError = null
            } catch (e: Exception) {
                loadError = "Failed to load signing history"
            } finally {
                isLoading = false
                isLoadingMore = false
            }
        }
    }

    LaunchedEffect(Unit) {
        try {
            availableApps = permissionStore.getDistinctAuditCallers()
        } catch (e: Exception) {
            loadError = "Failed to load apps"
        }
    }

    LaunchedEffect(selectedApp) {
        loadLogs(reset = true)
    }

    val shouldLoadMore by remember {
        derivedStateOf {
            val lastVisibleItem = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
            lastVisibleItem >= logs.size - 5 && hasMore && !isLoadingMore && !isLoading
        }
    }

    LaunchedEffect(shouldLoadMore) {
        if (shouldLoadMore) {
            loadLogs(reset = false)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
    ) {
        Text(
            text = "Signing History",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "View past signing requests and decisions",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(16.dp))

        if (availableApps.isNotEmpty()) {
            ExposedDropdownMenuBox(
                expanded = appFilterExpanded,
                onExpandedChange = { appFilterExpanded = it }
            ) {
                OutlinedTextField(
                    value = selectedApp ?: "All apps",
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Filter by app") },
                    trailingIcon = {
                        Icon(
                            Icons.Default.KeyboardArrowDown,
                            contentDescription = null
                        )
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .menuAnchor()
                )
                ExposedDropdownMenu(
                    expanded = appFilterExpanded,
                    onDismissRequest = { appFilterExpanded = false }
                ) {
                    DropdownMenuItem(
                        text = { Text("All apps") },
                        onClick = {
                            selectedApp = null
                            appFilterExpanded = false
                        }
                    )
                    availableApps.forEach { app ->
                        DropdownMenuItem(
                            text = { Text(app, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                            onClick = {
                                selectedApp = app
                                appFilterExpanded = false
                            }
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }

        if (isLoading) {
            Box(modifier = Modifier.weight(1f), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
        } else if (logs.isEmpty()) {
            Box(modifier = Modifier.weight(1f), contentAlignment = Alignment.Center) {
                Text(
                    text = "No signing history",
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                state = listState,
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(
                    items = logs,
                    key = { it.id }
                ) { log ->
                    AuditLogCard(log)
                }

                if (isLoadingMore) {
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(24.dp))
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        TextButton(
            onClick = onDismiss,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Back")
        }
    }
}

@Composable
private fun AuditLogCard(log: Nip55AuditLog) {
    val dateFormat = remember { SimpleDateFormat("MMM d, yyyy HH:mm:ss", Locale.getDefault()) }
    val isAllowed = log.decision == "allow"

    val containerColor = if (isAllowed)
        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
    else
        MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.5f)

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = formatRequestType(log.requestType),
                    style = MaterialTheme.typography.titleSmall
                )
                DecisionBadge(decision = log.decision, wasAutomatic = log.wasAutomatic)
            }

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = log.callerPackage,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )

            log.eventKind?.let { kind ->
                Text(
                    text = eventKindName(kind),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = dateFormat.format(Date(log.timestamp)),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun DecisionBadge(decision: String, wasAutomatic: Boolean) {
    val isAllowed = decision == "allow"
    val backgroundColor = if (isAllowed)
        MaterialTheme.colorScheme.primary
    else
        MaterialTheme.colorScheme.error

    Row(verticalAlignment = Alignment.CenterVertically) {
        if (wasAutomatic) {
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = MaterialTheme.shapes.small
            ) {
                Text(
                    text = "Auto",
                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(modifier = Modifier.width(4.dp))
        }
        Surface(
            color = backgroundColor,
            shape = MaterialTheme.shapes.small
        ) {
            Text(
                text = if (isAllowed) "Allowed" else "Denied",
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                style = MaterialTheme.typography.labelSmall,
                color = if (isAllowed)
                    MaterialTheme.colorScheme.onPrimary
                else
                    MaterialTheme.colorScheme.onError
            )
        }
    }
}
