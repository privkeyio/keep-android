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
import androidx.compose.material.icons.filled.ArrowBack
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
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectedAppsScreen(
    permissionStore: PermissionStore,
    onAppClick: (String) -> Unit,
    onDismiss: () -> Unit
) {
    var connectedApps by remember { mutableStateOf<List<ConnectedAppInfo>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        connectedApps = withContext(Dispatchers.IO) { permissionStore.getConnectedApps() }
        isLoading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Connected Apps") },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
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
        } else if (connectedApps.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        "No connected apps",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        "Apps that request signing permissions will appear here",
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
private fun ConnectedAppItem(
    app: ConnectedAppInfo,
    onClick: () -> Unit
) {
    val context = LocalContext.current
    var appLabel by remember { mutableStateOf<String?>(null) }
    var appIcon by remember { mutableStateOf<Drawable?>(null) }
    var isVerified by remember { mutableStateOf(true) }

    LaunchedEffect(app.packageName) {
        val (fetchedLabel, fetchedIcon, verified) = withContext(Dispatchers.IO) {
            try {
                val pm = context.packageManager
                val info = pm.getApplicationInfo(app.packageName, 0)
                Triple(
                    pm.getApplicationLabel(info).toString(),
                    pm.getApplicationIcon(info),
                    true
                )
            } catch (e: PackageManager.NameNotFoundException) {
                Log.e("ConnectedApps", "Failed to verify app package: ${app.packageName}", e)
                Triple(null, null, false)
            }
        }
        appLabel = fetchedLabel
        appIcon = fetchedIcon
        isVerified = verified
    }

    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            val icon = appIcon
            if (icon != null) {
                Image(
                    bitmap = icon.toBitmap(48, 48).asImageBitmap(),
                    contentDescription = null,
                    modifier = Modifier.size(48.dp)
                )
            } else {
                Box(
                    modifier = Modifier.size(48.dp),
                    contentAlignment = Alignment.Center
                ) {
                    if (!isVerified) {
                        Icon(
                            Icons.Default.Warning,
                            contentDescription = "Unverified",
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(32.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.width(16.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = appLabel ?: app.packageName,
                    style = MaterialTheme.typography.titleMedium
                )
                if (appLabel != null) {
                    Text(
                        text = app.packageName,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Spacer(modifier = Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    Text(
                        text = "${app.permissionCount} permission${if (app.permissionCount != 1) "s" else ""}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    app.lastUsedTime?.let { time ->
                        Text(
                            text = "Last used: ${formatTime(time)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                if (!isVerified) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "App not installed",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}

private fun formatTime(timestamp: Long): String {
    val now = System.currentTimeMillis()
    val diff = now - timestamp
    return when {
        diff < 60_000 -> "just now"
        diff < 3600_000 -> "${diff / 60_000}m ago"
        diff < 86400_000 -> "${diff / 3600_000}h ago"
        diff < 604800_000 -> "${diff / 86400_000}d ago"
        else -> SimpleDateFormat("MMM d", Locale.getDefault()).format(Date(timestamp))
    }
}
