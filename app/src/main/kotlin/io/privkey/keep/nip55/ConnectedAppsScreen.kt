package io.privkey.keep.nip55

import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.util.Log
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.privkey.keep.BuildConfig
import io.privkey.keep.R
import io.privkey.keep.nip46.Nip46ClientStore
import io.privkey.keep.ui.components.AppAvatar
import io.privkey.keep.ui.components.KeepCard
import io.privkey.keep.ui.components.KeepEmptyState
import io.privkey.keep.ui.components.KeepScreenScaffold
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private data class AppInfoResult(
    val label: String?,
    val icon: Drawable?,
    val verified: Boolean
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectedAppsScreen(
    permissionStore: PermissionStore,
    onAppClick: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    var connectedApps by remember { mutableStateOf<List<ConnectedAppInfo>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var loadError by remember { mutableStateOf<String?>(null) }
    val errLoad = stringResource(R.string.connections_app_load_error_state)

    LaunchedEffect(Unit) {
        try {
            val nip55Apps = withContext(Dispatchers.IO) { permissionStore.getConnectedApps() }
            val nip46Clients = withContext(Dispatchers.IO) {
                val clients = Nip46ClientStore.getClients(context).values
                val auditLog = if (clients.isNotEmpty()) permissionStore.getAuditLog(100) else emptyList()
                clients.map { client ->
                    val callerPackage = "nip46:${client.pubkey}"
                    val permCount = permissionStore.getPermissionsForCaller(callerPackage).size
                    val lastUsed = auditLog
                        .filter { it.callerPackage == callerPackage }
                        .maxOfOrNull { it.timestamp }
                    ConnectedAppInfo(
                        packageName = callerPackage,
                        permissionCount = permCount,
                        lastUsedTime = lastUsed ?: client.connectedAt,
                        expiresAt = null
                    )
                }
            }
            connectedApps = (nip55Apps + nip46Clients).sortedByDescending { it.lastUsedTime ?: 0L }
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.e("ConnectedApps", "Failed to load connected apps", e)
            loadError = errLoad
        }
        isLoading = false
    }

    KeepScreenScaffold(
        title = stringResource(R.string.connected_apps),
        onBack = onDismiss
    ) { padding ->
        if (isLoading) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator()
            }
        } else if (loadError != null) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                KeepEmptyState(
                    icon = Icons.Default.Warning,
                    title = stringResource(R.string.connected_apps_load_error),
                    subtitle = loadError
                )
            }
        } else if (connectedApps.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                KeepEmptyState(
                    icon = Icons.Default.Apps,
                    title = stringResource(R.string.no_connected_apps),
                    subtitle = stringResource(R.string.connected_apps_description)
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(connectedApps, key = { it.packageName }) { app ->
                    ConnectedAppItem(app = app, onClick = { onAppClick(app.packageName) })
                }
            }
        }
    }
}

@Composable
private fun ConnectedAppItem(
    app: ConnectedAppInfo,
    onClick: () -> Unit
) {
    val context = LocalContext.current
    var appLabel by remember { mutableStateOf<String?>(null) }
    var appIcon by remember { mutableStateOf<Drawable?>(null) }
    var isVerified by remember { mutableStateOf(true) }
    val isNip46Client = app.packageName.startsWith("nip46:")
    val nip46RowLabel = stringResource(R.string.connections_app_nip46_client_row_label)

    LaunchedEffect(app.packageName) {
        if (isNip46Client) {
            val pubkey = app.packageName.removePrefix("nip46:")
            val clientInfo = Nip46ClientStore.getClient(context, pubkey)
            appLabel = clientInfo?.name ?: nip46RowLabel
            appIcon = null
            isVerified = true
        } else {
            val result = withContext(Dispatchers.IO) {
                try {
                    val pm = context.packageManager
                    val info = pm.getApplicationInfo(app.packageName, 0)
                    AppInfoResult(
                        label = pm.getApplicationLabel(info).toString(),
                        icon = pm.getApplicationIcon(info),
                        verified = true
                    )
                } catch (e: PackageManager.NameNotFoundException) {
                    if (BuildConfig.DEBUG) Log.w("ConnectedApps", "Package not found")
                    AppInfoResult(label = null, icon = null, verified = false)
                }
            }
            appLabel = result.label
            appIcon = result.icon
            isVerified = result.verified
        }
    }

    KeepCard(onClick = onClick) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            AppAvatar(
                key = app.packageName,
                name = appLabel,
                drawable = appIcon,
                unverified = !isVerified
            )

            Spacer(modifier = Modifier.width(16.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = appLabel ?: app.packageName,
                    style = MaterialTheme.typography.titleMedium
                )
                if (isNip46Client) {
                    val pubkey = app.packageName.removePrefix("nip46:")
                    Text(
                        text = stringResource(R.string.connections_app_nip46_row, io.privkey.keep.uniffi.truncateStr(pubkey, 8u, 6u)),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                } else if (appLabel != null) {
                    Text(
                        text = app.packageName,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Spacer(modifier = Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    Text(
                        text = pluralStringResource(R.plurals.connected_app_permission_count, app.permissionCount, app.permissionCount),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    app.lastUsedTime?.let { time ->
                        Text(
                            text = stringResource(R.string.connected_app_last_used, formatRelativeTime(time)),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                app.expiresAt?.let { expiry ->
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = stringResource(R.string.app_expires_in, formatExpiry(expiry)),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary
                    )
                }
                if (!isVerified) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = stringResource(R.string.connected_app_not_installed),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}

