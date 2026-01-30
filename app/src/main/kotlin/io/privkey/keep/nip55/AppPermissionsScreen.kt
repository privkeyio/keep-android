package io.privkey.keep.nip55

import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.*

private data class AppState(
    val label: String? = null,
    val icon: Drawable? = null,
    val isVerified: Boolean = true,
    val permissions: List<Nip55Permission> = emptyList(),
    val isLoading: Boolean = true
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppPermissionsScreen(
    packageName: String,
    permissionStore: PermissionStore,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var appState by remember { mutableStateOf(AppState()) }
    var showRevokeAllDialog by remember { mutableStateOf(false) }

    LaunchedEffect(packageName) {
        appState = withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val (label, icon, verified) = try {
                val appInfo = pm.getApplicationInfo(packageName, 0)
                Triple(
                    pm.getApplicationLabel(appInfo).toString(),
                    pm.getApplicationIcon(appInfo),
                    true
                )
            } catch (e: PackageManager.NameNotFoundException) {
                android.util.Log.e("AppPermissions", "Failed to verify app package: $packageName", e)
                Triple(null, null, false)
            }
            val permissions = try {
                permissionStore.getPermissionsForCaller(packageName)
            } catch (e: Exception) {
                android.util.Log.e("AppPermissions", "Failed to load permissions for: $packageName", e)
                emptyList()
            }
            AppState(label, icon, verified, permissions, isLoading = false)
        }
    }

    if (showRevokeAllDialog) {
        AlertDialog(
            onDismissRequest = { showRevokeAllDialog = false },
            title = { Text("Disconnect App?") },
            text = { Text("This will remove all saved permissions for ${appState.label ?: packageName}. The app will need to request permission again.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        coroutineScope.launch {
                            withContext(Dispatchers.IO) {
                                permissionStore.revokePermission(packageName)
                            }
                            showRevokeAllDialog = false
                            onDismiss()
                        }
                    },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                ) {
                    Text("Disconnect")
                }
            },
            dismissButton = {
                TextButton(onClick = { showRevokeAllDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(appState.label ?: packageName) },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                AppHeaderCard(
                    packageName = packageName,
                    appLabel = appState.label,
                    appIcon = appState.icon,
                    isVerified = appState.isVerified
                )
            }

            if (appState.isLoading) {
                item {
                    Box(
                        modifier = Modifier.fillMaxWidth().padding(32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        CircularProgressIndicator()
                    }
                }
            } else if (appState.permissions.isEmpty()) {
                item {
                    Text(
                        "No active permissions",
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                item {
                    Text(
                        "Permissions",
                        style = MaterialTheme.typography.titleMedium
                    )
                }
                items(appState.permissions, key = { it.id }) { permission ->
                    var updateError by remember { mutableStateOf<String?>(null) }
                    val requestType = findRequestType(permission.requestType)

                    PermissionItem(
                        permission = permission,
                        onDecisionChange = { newDecision ->
                            if (requestType == null) return@PermissionItem
                            coroutineScope.launch {
                                try {
                                    withContext(Dispatchers.IO) {
                                        permissionStore.updatePermissionDecision(
                                            permission.id,
                                            newDecision,
                                            packageName,
                                            requestType,
                                            permission.eventKind
                                        )
                                    }
                                    val newPermissions = withContext(Dispatchers.IO) {
                                        permissionStore.getPermissionsForCaller(packageName)
                                    }
                                    appState = appState.copy(permissions = newPermissions)
                                    updateError = null
                                } catch (e: Exception) {
                                    android.util.Log.e("AppPermissions", "Failed to update permission", e)
                                    updateError = "Failed to update permission"
                                }
                            }
                        },
                        errorMessage = updateError,
                        onRevoke = {
                            coroutineScope.launch {
                                withContext(Dispatchers.IO) {
                                    permissionStore.deletePermission(permission.id)
                                }
                                val newPermissions = withContext(Dispatchers.IO) {
                                    permissionStore.getPermissionsForCaller(packageName)
                                }
                                appState = appState.copy(permissions = newPermissions)
                                if (newPermissions.isEmpty()) onDismiss()
                            }
                        }
                    )
                }
            }

            item {
                Spacer(modifier = Modifier.height(8.dp))
                Button(
                    onClick = { showRevokeAllDialog = true },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                ) {
                    Text("Disconnect App")
                }
            }
        }
    }
}

@Composable
private fun AppHeaderCard(
    packageName: String,
    appLabel: String?,
    appIcon: Drawable?,
    isVerified: Boolean
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (appIcon != null) {
                Image(
                    bitmap = appIcon.toBitmap(64, 64).asImageBitmap(),
                    contentDescription = null,
                    modifier = Modifier.size(64.dp)
                )
            } else {
                Box(
                    modifier = Modifier.size(64.dp),
                    contentAlignment = Alignment.Center
                ) {
                    if (!isVerified) {
                        Icon(
                            Icons.Default.Warning,
                            contentDescription = "Unverified",
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(48.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.width(16.dp))

            Column {
                Text(
                    text = appLabel ?: packageName,
                    style = MaterialTheme.typography.titleLarge
                )
                if (appLabel != null) {
                    Text(
                        text = packageName,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (!isVerified) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer
                        )
                    ) {
                        Text(
                            text = "Warning: App not installed or unverified",
                            modifier = Modifier.padding(8.dp),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun PermissionItem(
    permission: Nip55Permission,
    onDecisionChange: (PermissionDecision) -> Unit,
    onRevoke: () -> Unit,
    errorMessage: String? = null
) {
    val currentDecision = permission.permissionDecision

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = formatRequestType(permission.requestType),
                        style = MaterialTheme.typography.titleSmall
                    )
                    permission.eventKind?.let { kind ->
                        Text(
                            text = "Event kind: $kind",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    val expiryText = permission.expiresAt?.let { "Expires: ${formatExpiry(it)}" } ?: "Permanent"
                    Text(
                        text = expiryText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                IconButton(onClick = onRevoke) {
                    Icon(
                        Icons.Default.Delete,
                        contentDescription = "Revoke",
                        tint = MaterialTheme.colorScheme.error
                    )
                }
            }

            errorMessage?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            ThreeStateToggle(
                currentDecision = currentDecision,
                onDecisionChange = onDecisionChange
            )
        }
    }
}

private fun formatExpiry(timestamp: Long): String {
    val remaining = timestamp - System.currentTimeMillis()
    return when {
        remaining < 0 -> "Expired"
        remaining < 3600_000 -> "${remaining / 60_000}m remaining"
        remaining < 86400_000 -> "${remaining / 3600_000}h remaining"
        else -> SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()).format(Date(timestamp))
    }
}
