package io.privkey.keep.nip55

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.privkey.keep.R
import kotlinx.coroutines.launch

@Composable
fun PermissionsManagementScreen(
    permissionStore: PermissionStore,
    onDismiss: () -> Unit
) {
    var permissions by remember { mutableStateOf<List<Nip55Permission>>(emptyList()) }
    var velocityUsage by remember { mutableStateOf<Map<String, Triple<Int, Int, Int>>>(emptyMap()) }
    var isLoading by remember { mutableStateOf(true) }
    var loadError by remember { mutableStateOf<String?>(null) }
    var showRevokeAllDialog by remember { mutableStateOf<String?>(null) }
    var showDeleteDialog by remember { mutableStateOf<Nip55Permission?>(null) }
    val coroutineScope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }

    val errLoad = stringResource(R.string.connections_permissions_load_error)
    val errRefresh = stringResource(R.string.connections_permissions_refresh_error)
    val errUpdate = stringResource(R.string.connections_permissions_update_error)
    val errRevoke = stringResource(R.string.connections_permissions_revoke_error)
    val errDelete = stringResource(R.string.connections_permissions_delete_error)
    val errUnknownTypeFormat = stringResource(R.string.connections_permissions_unknown_type)

    suspend fun loadPermissionsData() {
        val loadedPermissions = permissionStore.getAllPermissions()
        permissions = loadedPermissions
        val packages = loadedPermissions.map { it.callerPackage }.distinct()
        velocityUsage = packages.associateWith { permissionStore.getVelocityUsage(it) }
    }

    LaunchedEffect(Unit) {
        try {
            loadPermissionsData()
        } catch (e: Exception) {
            loadError = errLoad
        } finally {
            isLoading = false
        }
    }

    fun refreshPermissions() {
        coroutineScope.launch {
            try {
                loadPermissionsData()
                loadError = null
            } catch (e: Exception) {
                loadError = errRefresh
            }
        }
    }

    LaunchedEffect(loadError) {
        loadError?.let {
            snackbarHostState.showSnackbar(it)
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(24.dp)
        ) {
            Text(
                text = stringResource(R.string.connections_permissions_title),
                style = MaterialTheme.typography.headlineMedium
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = stringResource(R.string.connections_permissions_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(16.dp))

            if (isLoading) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            } else if (permissions.isEmpty()) {
                Box(modifier = Modifier.weight(1f), contentAlignment = Alignment.Center) {
                    Text(
                        text = stringResource(R.string.connections_permissions_none),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                PermissionsGroupedList(
                    permissions = permissions,
                    velocityUsage = velocityUsage,
                    modifier = Modifier.weight(1f),
                    onRevokeAll = { showRevokeAllDialog = it },
                    onDecisionChange = { permission, newDecision ->
                        val requestType = findRequestType(permission.requestType)
                        if (requestType == null) {
                            loadError = String.format(errUnknownTypeFormat, permission.requestType)
                            return@PermissionsGroupedList
                        }
                        coroutineScope.launch {
                            try {
                                permissionStore.updatePermissionDecision(
                                    permission.id,
                                    newDecision,
                                    permission.callerPackage,
                                    requestType,
                                    permission.eventKind
                                )
                                refreshPermissions()
                            } catch (e: Exception) {
                                loadError = errUpdate
                            }
                        }
                    },
                    onDelete = { showDeleteDialog = it }
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.back))
            }
        }
    }

    showRevokeAllDialog?.let { packageName ->
        RevokeAllPermissionsDialog(
            packageName = packageName,
            onConfirm = {
                coroutineScope.launch {
                    try {
                        permissionStore.revokeAllForApp(packageName)
                        refreshPermissions()
                    } catch (e: Exception) {
                        loadError = errRevoke
                    }
                }
                showRevokeAllDialog = null
            },
            onDismiss = { showRevokeAllDialog = null }
        )
    }

    showDeleteDialog?.let { permission ->
        DeletePermissionDialog(
            permission = permission,
            onConfirm = {
                coroutineScope.launch {
                    try {
                        permissionStore.deletePermission(permission.id)
                        refreshPermissions()
                    } catch (e: Exception) {
                        loadError = errDelete
                    }
                }
                showDeleteDialog = null
            },
            onDismiss = { showDeleteDialog = null }
        )
    }
}

@Composable
private fun RevokeAllPermissionsDialog(
    packageName: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.connections_permissions_revoke_all_title)) },
        text = { Text(stringResource(R.string.connections_permissions_revoke_all_text, packageName)) },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.connections_permissions_revoke_all_confirm), color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.connections_permissions_cancel))
            }
        }
    )
}

@Composable
private fun DeletePermissionDialog(
    permission: Nip55Permission,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.connections_permissions_delete_title)) },
        text = {
            Text(stringResource(R.string.connections_permissions_delete_text, formatRequestType(permission.requestType), permission.callerPackage))
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.connections_permissions_delete_confirm), color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.connections_permissions_cancel))
            }
        }
    )
}

@Composable
private fun PermissionsGroupedList(
    permissions: List<Nip55Permission>,
    velocityUsage: Map<String, Triple<Int, Int, Int>>,
    modifier: Modifier = Modifier,
    onRevokeAll: (String) -> Unit,
    onDecisionChange: (Nip55Permission, PermissionDecision) -> Unit,
    onDelete: (Nip55Permission) -> Unit
) {
    val groupedPermissions = remember(permissions) { permissions.groupBy { it.callerPackage } }

    LazyColumn(
        modifier = modifier,
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        groupedPermissions.forEach { (packageName, appPermissions) ->
            item(key = "header_$packageName") {
                AppPermissionHeader(
                    packageName = packageName,
                    permissionCount = appPermissions.size,
                    velocityUsage = velocityUsage[packageName],
                    onRevokeAll = { onRevokeAll(packageName) }
                )
            }
            items(
                items = appPermissions,
                key = { it.id }
            ) { permission ->
                PermissionCard(
                    permission = permission,
                    onDecisionChange = { newDecision ->
                        onDecisionChange(permission, newDecision)
                    },
                    onDelete = { onDelete(permission) }
                )
            }
            item(key = "spacer_$packageName") {
                Spacer(modifier = Modifier.height(8.dp))
            }
        }
    }
}

@Composable
private fun AppPermissionHeader(
    packageName: String,
    permissionCount: Int,
    velocityUsage: Triple<Int, Int, Int>?,
    onRevokeAll: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = packageName,
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = pluralStringResource(R.plurals.connections_permissions_count, permissionCount, permissionCount),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            velocityUsage?.let { (hour, day, week) ->
                if (hour > 0 || day > 0 || week > 0) {
                    Text(
                        text = stringResource(R.string.connections_permissions_rate, hour, day, week),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 2.dp)
                    )
                }
            }
        }
        TextButton(onClick = onRevokeAll) {
            Text(stringResource(R.string.connections_permissions_revoke_all_header), color = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
private fun PermissionCard(
    permission: Nip55Permission,
    onDecisionChange: (PermissionDecision) -> Unit,
    onDelete: () -> Unit
) {
    val isExpired = permission.isExpired()
    val currentDecision = permission.permissionDecision
    val context = LocalContext.current
    val containerColor = if (isExpired) {
        MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f)
    } else {
        when (currentDecision) {
            PermissionDecision.DENY -> MaterialTheme.colorScheme.errorContainer
            PermissionDecision.ASK -> MaterialTheme.colorScheme.tertiaryContainer
            else -> MaterialTheme.colorScheme.surfaceVariant
        }
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
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = formatRequestType(permission.requestType),
                            style = MaterialTheme.typography.bodyLarge
                        )
                        if (isExpired) {
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = stringResource(R.string.connections_permissions_expired),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }

                    permission.eventKindOrNull?.let { kind ->
                        Text(
                            text = EventKind.displayName(context, kind),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        if (kind == KIND_NIP42_AUTH && permission.relay != RELAY_NONE) {
                            val relayLabel = if (permission.relay == RELAY_WILDCARD) {
                                stringResource(R.string.connections_nip55_relay_scope_all)
                            } else {
                                permission.relay
                            }
                            Text(
                                text = stringResource(R.string.connections_permissions_relay_scope, relayLabel),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    val expiryText = permission.expiresAt?.let { stringResource(R.string.connections_permissions_expires, io.privkey.keep.uniffi.formatTimestampDetailed(it / 1000)) } ?: stringResource(R.string.connections_permissions_permanent)
                    Text(
                        text = expiryText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                IconButton(onClick = onDelete) {
                    Icon(
                        Icons.Default.Delete,
                        contentDescription = stringResource(R.string.connections_permissions_delete_cd),
                        tint = MaterialTheme.colorScheme.error
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            ThreeStateToggle(
                currentDecision = currentDecision,
                onDecisionChange = onDecisionChange
            )
        }
    }
}
