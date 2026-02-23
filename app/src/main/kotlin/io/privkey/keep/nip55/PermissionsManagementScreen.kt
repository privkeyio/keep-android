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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

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
            loadError = "Failed to load permissions"
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
                loadError = "Failed to refresh permissions"
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
                text = "App Permissions",
                style = MaterialTheme.typography.headlineMedium
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Manage NIP-55 permissions granted to apps",
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
                        text = "No permissions granted",
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
                        val requestType = findRequestType(permission.requestType) ?: return@PermissionsGroupedList
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
                                loadError = "Failed to update permission"
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
                Text("Back")
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
                        loadError = "Failed to revoke permissions"
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
                        loadError = "Failed to delete permission"
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
        title = { Text("Revoke All Permissions") },
        text = { Text("Revoke all permissions for $packageName? This app will need to request permissions again.") },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text("Revoke All", color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
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
        title = { Text("Delete Permission") },
        text = {
            Text("Delete this ${formatRequestType(permission.requestType)} permission for ${permission.callerPackage}?")
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text("Delete", color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
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
    val groupedPermissions = permissions.groupBy { it.callerPackage }

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
                text = "$permissionCount permission${if (permissionCount != 1) "s" else ""}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            velocityUsage?.let { (hour, day, week) ->
                if (hour > 0 || day > 0 || week > 0) {
                    Text(
                        text = "Rate: $hour/h \u00b7 $day/d \u00b7 $week/w",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 2.dp)
                    )
                }
            }
        }
        TextButton(onClick = onRevokeAll) {
            Text("Revoke All", color = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
private fun PermissionCard(
    permission: Nip55Permission,
    onDecisionChange: (PermissionDecision) -> Unit,
    onDelete: () -> Unit
) {
    val dateFormat = remember { SimpleDateFormat("MMM d, yyyy HH:mm", Locale.getDefault()) }
    val isExpired = permission.isExpired()
    val currentDecision = permission.permissionDecision
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
                                text = "Expired",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }

                    permission.eventKindOrNull?.let { kind ->
                        Text(
                            text = EventKind.displayName(kind),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    val expiryText = permission.expiresAt?.let { "Expires ${dateFormat.format(Date(it))}" } ?: "Permanent"
                    Text(
                        text = expiryText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                IconButton(onClick = onDelete) {
                    Icon(
                        Icons.Default.Delete,
                        contentDescription = "Delete permission",
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
