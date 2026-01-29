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
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.*

private data class Tuple4<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppPermissionsScreen(
    packageName: String,
    permissionStore: PermissionStore,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var permissions by remember { mutableStateOf<List<Nip55Permission>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var appLabel by remember { mutableStateOf<String?>(null) }
    var appIcon by remember { mutableStateOf<Drawable?>(null) }
    var isVerified by remember { mutableStateOf(true) }
    var showRevokeAllDialog by remember { mutableStateOf(false) }

    LaunchedEffect(packageName) {
        val (fetchedLabel, fetchedIcon, verified, perms) = withContext(Dispatchers.IO) {
            var label: String? = null
            var icon: Drawable? = null
            var ver = true
            try {
                val pm = context.packageManager
                val info = pm.getApplicationInfo(packageName, 0)
                label = pm.getApplicationLabel(info).toString()
                icon = pm.getApplicationIcon(info)
            } catch (e: PackageManager.NameNotFoundException) {
                ver = false
            }
            val permsList = permissionStore.getPermissionsForCaller(packageName)
            Tuple4(label, icon, ver, permsList)
        }
        withContext(Dispatchers.Main) {
            appLabel = fetchedLabel
            appIcon = fetchedIcon
            isVerified = verified
            permissions = perms
            isLoading = false
        }
    }

    if (showRevokeAllDialog) {
        AlertDialog(
            onDismissRequest = { showRevokeAllDialog = false },
            title = { Text("Disconnect App?") },
            text = { Text("This will remove all saved permissions for ${appLabel ?: packageName}. The app will need to request permission again.") },
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
                title = { Text(appLabel ?: packageName) },
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
                    appLabel = appLabel,
                    appIcon = appIcon,
                    isVerified = isVerified
                )
            }

            if (isLoading) {
                item {
                    Box(
                        modifier = Modifier.fillMaxWidth().padding(32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        CircularProgressIndicator()
                    }
                }
            } else if (permissions.isEmpty()) {
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
                items(permissions, key = { it.id }) { permission ->
                    PermissionItem(
                        permission = permission,
                        onRevoke = {
                            coroutineScope.launch {
                                withContext(Dispatchers.IO) {
                                    val requestType = Nip55RequestType.entries
                                        .find { it.name == permission.requestType }
                                    if (requestType != null) {
                                        permissionStore.revokePermission(packageName, requestType)
                                    }
                                }
                                permissions = withContext(Dispatchers.IO) {
                                    permissionStore.getPermissionsForCaller(packageName)
                                }
                                if (permissions.isEmpty()) onDismiss()
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
    onRevoke: () -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.padding(16.dp),
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
                Text(
                    text = "Decision: ${permission.decision}",
                    style = MaterialTheme.typography.bodySmall,
                    color = if (permission.decision == "allow") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                )
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
    }
}

private fun formatRequestType(type: String): String = type
    .replace("_", " ")
    .lowercase()
    .replaceFirstChar { it.uppercase() }

private fun formatExpiry(timestamp: Long): String {
    val remaining = timestamp - System.currentTimeMillis()
    return when {
        remaining < 0 -> "Expired"
        remaining < 3600_000 -> "${remaining / 60_000}m remaining"
        remaining < 86400_000 -> "${remaining / 3600_000}h remaining"
        else -> SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()).format(Date(timestamp))
    }
}
