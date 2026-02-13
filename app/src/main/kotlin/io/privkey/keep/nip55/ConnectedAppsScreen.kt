package io.privkey.keep.nip55

import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.util.Log
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import io.privkey.keep.BuildConfig
import io.privkey.keep.R
import io.privkey.keep.nip46.Nip46ClientStore
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
            loadError = "Failed to load connected apps"
        }
        isLoading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.connected_apps)) },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                    }
                }
            )
        },
        containerColor = MaterialTheme.colorScheme.background
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
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Default.Warning,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        stringResource(R.string.connected_apps_load_error),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.error
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        loadError!!,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else if (connectedApps.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        stringResource(R.string.no_connected_apps),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.connected_apps_description),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
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
private fun AppIconBox(
    icon: Drawable?,
    isNip46Client: Boolean,
    isVerified: Boolean
) {
    when {
        icon != null -> {
            Image(
                bitmap = icon.toBitmap(48, 48).asImageBitmap(),
                contentDescription = null,
                modifier = Modifier.size(48.dp)
            )
        }
        isNip46Client -> {
            Box(
                modifier = Modifier.size(48.dp),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Default.Cloud,
                    contentDescription = "NIP-46 Client",
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(32.dp)
                )
            }
        }
        !isVerified -> {
            Box(
                modifier = Modifier.size(48.dp),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Default.Warning,
                    contentDescription = stringResource(R.string.connected_app_unverified),
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(32.dp)
                )
            }
        }
        else -> {
            Spacer(modifier = Modifier.size(48.dp))
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

    LaunchedEffect(app.packageName) {
        if (isNip46Client) {
            val pubkey = app.packageName.removePrefix("nip46:")
            val clientInfo = Nip46ClientStore.getClient(context, pubkey)
            appLabel = clientInfo?.name ?: "NIP-46 Client"
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

    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            AppIconBox(
                icon = appIcon,
                isNip46Client = isNip46Client,
                isVerified = isVerified
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
                        text = "NIP-46 (${pubkey.take(8)}...${pubkey.takeLast(6)})",
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

