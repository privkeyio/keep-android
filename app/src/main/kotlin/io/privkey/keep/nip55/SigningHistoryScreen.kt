package io.privkey.keep.nip55

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

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
    var chainStatus by remember { mutableStateOf<ChainVerificationResult?>(null) }
    var logCount by remember { mutableIntStateOf(0) }
    val coroutineScope = rememberCoroutineScope()
    val listState = rememberLazyListState()

    var loadError by remember { mutableStateOf<String?>(null) }

    fun loadLogs(reset: Boolean = false) {
        coroutineScope.launch {
            if (reset) isLoading = true else isLoadingMore = true

            runCatching {
                val offset = if (reset) 0 else logs.size
                permissionStore.getAuditLogPage(
                    limit = PAGE_SIZE,
                    offset = offset,
                    callerPackage = selectedApp
                )
            }.onSuccess { newLogs ->
                logs = if (reset) newLogs else logs + newLogs
                hasMore = newLogs.size == PAGE_SIZE
                loadError = null
            }.onFailure {
                loadError = "Failed to load signing history"
            }

            isLoading = false
            isLoadingMore = false
        }
    }

    LaunchedEffect(Unit) {
        try {
            availableApps = permissionStore.getDistinctAuditCallers()
            chainStatus = permissionStore.verifyAuditChain()
            logCount = permissionStore.getAuditLogCount()
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
            .statusBarsPadding()
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

        Spacer(modifier = Modifier.height(12.dp))

        ChainStatusIndicator(status = chainStatus, entryCount = logCount)

        Spacer(modifier = Modifier.height(12.dp))

        loadError?.let { error ->
            Text(
                text = error,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium
            )
            Spacer(modifier = Modifier.height(12.dp))
        }

        if (availableApps.isNotEmpty()) {
            AppFilterDropdown(
                availableApps = availableApps,
                selectedApp = selectedApp,
                expanded = appFilterExpanded,
                onExpandedChange = { appFilterExpanded = it },
                onAppSelected = { app ->
                    selectedApp = app
                    appFilterExpanded = false
                }
            )

            Spacer(modifier = Modifier.height(16.dp))
        }

        SigningHistoryLogsList(
            logs = logs,
            isLoading = isLoading,
            isLoadingMore = isLoadingMore,
            listState = listState,
            modifier = Modifier.weight(1f)
        )

        Spacer(modifier = Modifier.height(16.dp))

        TextButton(
            onClick = onDismiss,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Back")
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppFilterDropdown(
    availableApps: List<String>,
    selectedApp: String?,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    onAppSelected: (String?) -> Unit
) {
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = onExpandedChange
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
                .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable)
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { onExpandedChange(false) }
        ) {
            DropdownMenuItem(
                text = { Text("All apps") },
                onClick = { onAppSelected(null) }
            )
            availableApps.forEach { app ->
                DropdownMenuItem(
                    text = { Text(app, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    onClick = { onAppSelected(app) }
                )
            }
        }
    }
}

@Composable
private fun SigningHistoryLogsList(
    logs: List<Nip55AuditLog>,
    isLoading: Boolean,
    isLoadingMore: Boolean,
    listState: LazyListState,
    modifier: Modifier = Modifier
) {
    if (isLoading) {
        Box(modifier = modifier, contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
    } else if (logs.isEmpty()) {
        Box(modifier = modifier, contentAlignment = Alignment.Center) {
            Text(
                text = "No signing history",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    } else {
        LazyColumn(
            modifier = modifier,
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
}

@Composable
private fun AuditLogCard(log: Nip55AuditLog) {
    val isAllowed = log.decision == "allow"

    val containerColor = if (isAllowed) {
        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
    } else {
        MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.5f)
    }

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
                    text = EventKind.displayName(kind),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = io.privkey.keep.uniffi.formatTimestampDetailed(log.timestamp / 1000),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun DecisionBadge(decision: String, wasAutomatic: Boolean) {
    val isAllowed = decision == "allow"

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
            color = if (isAllowed) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            shape = MaterialTheme.shapes.small
        ) {
            Text(
                text = if (isAllowed) "Allowed" else "Denied",
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                style = MaterialTheme.typography.labelSmall,
                color = if (isAllowed) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onError
            )
        }
    }
}

@Composable
private fun ChainStatusIndicator(status: ChainVerificationResult?, entryCount: Int) {
    val isError = status is ChainVerificationResult.Broken || status is ChainVerificationResult.Tampered
    val icon = if (isError) Icons.Default.Warning else Icons.Default.CheckCircle
    val (statusText, statusColor) = when (status) {
        is ChainVerificationResult.Valid ->
            "Chain verified ($entryCount entries)" to MaterialTheme.colorScheme.primary
        is ChainVerificationResult.PartiallyVerified ->
            "Verified (${status.legacyEntriesSkipped} legacy entries)" to MaterialTheme.colorScheme.tertiary
        is ChainVerificationResult.Truncated ->
            "Verified (older entries pruned)" to MaterialTheme.colorScheme.tertiary
        is ChainVerificationResult.Broken ->
            "Chain integrity issue detected" to MaterialTheme.colorScheme.error
        is ChainVerificationResult.Tampered ->
            "Tampering detected in audit log" to MaterialTheme.colorScheme.error
        null ->
            "Verifying..." to MaterialTheme.colorScheme.onSurfaceVariant
    }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth()
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = statusColor,
            modifier = Modifier.size(16.dp)
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = statusText,
            style = MaterialTheme.typography.labelMedium,
            color = statusColor
        )
    }
}
