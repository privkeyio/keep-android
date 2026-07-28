package io.privkey.keep.nip55

import io.privkey.keep.ui.components.KeepCard
import android.graphics.drawable.Drawable
import android.util.Log
import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import io.privkey.keep.BuildConfig
import io.privkey.keep.R
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.nip46.BunkerConfigStore
import io.privkey.keep.nip46.BunkerService
import io.privkey.keep.nip46.Nip46ClientStore
import io.privkey.keep.storage.toSignPolicy
import io.privkey.keep.uniffi.BunkerConfigInfo
import io.privkey.keep.uniffi.SignPolicyStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private data class AppState(
    val label: String? = null,
    val icon: Drawable? = null,
    val isVerified: Boolean = true,
    val isNip46Client: Boolean = false,
    val permissions: List<Nip55Permission> = emptyList(),
    val signPolicyOverride: Int? = null,
    val isLoading: Boolean = true
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppPermissionsScreen(
    packageName: String,
    permissionStore: PermissionStore,
    signPolicyStore: SignPolicyStore? = null,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var appState by remember { mutableStateOf(AppState()) }
    var showRevokeAllDialog by remember { mutableStateOf(false) }
    var appSettings by remember { mutableStateOf<Nip55AppSettings?>(null) }
    var expiryDropdownExpanded by remember { mutableStateOf(false) }
    val nip46ClientLabel = stringResource(R.string.connections_app_nip46_client_label)

    LaunchedEffect(packageName) {
        val isNip46 = packageName.startsWith("nip46:")
        val (newAppState, settings) = withContext(Dispatchers.IO) {
            if (isNip46) {
                val pubkey = packageName.removePrefix("nip46:")
                val clientInfo = Nip46ClientStore.getClient(context, pubkey)
                val label = clientInfo?.name ?: nip46ClientLabel

                val permissions = runCatching { permissionStore.getPermissionsForCaller(packageName) }
                    .getOrDefault(emptyList())

                val loadedSettings = permissionStore.getAppSettings(packageName)
                val signPolicyOverride = runCatching { permissionStore.getAppSignPolicyOverride(packageName) }
                    .getOrNull()

                Pair(AppState(label, null, true, true, permissions, signPolicyOverride, isLoading = false), loadedSettings)
            } else {
                val pm = context.packageManager
                val pkgHash = packageName.hashCode().toString(16).takeLast(8)
                val appInfo = runCatching { pm.getApplicationInfo(packageName, 0) }
                    .onFailure { if (BuildConfig.DEBUG) Log.e("AppPermissions", "Failed to verify app package [hash:$pkgHash]", it) }
                    .getOrNull()

                val label = appInfo?.let { pm.getApplicationLabel(it).toString() }
                val icon = appInfo?.let { pm.getApplicationIcon(it) }
                val verified = appInfo != null

                val permissions = runCatching { permissionStore.getPermissionsForCaller(packageName) }
                    .onFailure { if (BuildConfig.DEBUG) Log.e("AppPermissions", "Failed to load permissions [hash:$pkgHash]", it) }
                    .getOrDefault(emptyList())

                val loadedSettings = permissionStore.getAppSettings(packageName)
                val signPolicyOverride = runCatching { permissionStore.getAppSignPolicyOverride(packageName) }
                    .onFailure { if (BuildConfig.DEBUG) Log.e("AppPermissions", "Failed to load sign policy [hash:$pkgHash]", it) }
                    .getOrNull()

                Pair(AppState(label, icon, verified, false, permissions, signPolicyOverride, isLoading = false), loadedSettings)
            }
        }
        appState = newAppState
        appSettings = settings
    }

    if (showRevokeAllDialog) {
        RevokeAllPermissionsDialog(
            packageName = packageName,
            appLabel = appState.label,
            permissionStore = permissionStore,
            coroutineScope = coroutineScope,
            onDismissDialog = { showRevokeAllDialog = false },
            onDismissScreen = onDismiss
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(appState.label ?: packageName) },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.connections_app_back_cd))
                    }
                }
            )
        }
    ) { padding ->
        AppPermissionsListContent(
            padding = padding,
            packageName = packageName,
            appState = appState,
            appSettings = appSettings,
            expiryDropdownExpanded = expiryDropdownExpanded,
            onExpiryDropdownExpandedChange = { expiryDropdownExpanded = it },
            signPolicyStore = signPolicyStore,
            permissionStore = permissionStore,
            coroutineScope = coroutineScope,
            onAppStateChange = { appState = it },
            onAppSettingsChange = { appSettings = it },
            onShowRevokeAllDialog = { showRevokeAllDialog = true },
            onDismiss = onDismiss
        )
    }
}

@Composable
private fun RevokeAllPermissionsDialog(
    packageName: String,
    appLabel: String?,
    permissionStore: PermissionStore,
    coroutineScope: CoroutineScope,
    onDismissDialog: () -> Unit,
    onDismissScreen: () -> Unit
) {
    val context = LocalContext.current
    val isNip46 = packageName.startsWith("nip46:")
    val dialogTitle = if (isNip46) stringResource(R.string.connections_app_disconnect_client_title) else stringResource(R.string.connections_app_disconnect_app_title)
    val dialogText = if (isNip46) {
        stringResource(R.string.connections_app_disconnect_client_text, appLabel ?: packageName)
    } else {
        stringResource(R.string.connections_app_disconnect_app_text, appLabel ?: packageName)
    }
    val toastRevokeFailed = stringResource(R.string.connections_app_revoke_toast_error)
    AlertDialog(
        onDismissRequest = onDismissDialog,
        title = { Text(dialogTitle) },
        text = { Text(dialogText) },
        confirmButton = {
            TextButton(
                onClick = {
                    coroutineScope.launch {
                        try {
                            withContext(Dispatchers.IO) {
                                permissionStore.revokePermission(packageName)
                                if (isNip46) {
                                    val pubkey = packageName.removePrefix("nip46:")
                                    revokeNip46Client(context, pubkey)
                                }
                            }
                            onDismissDialog()
                            onDismissScreen()
                        } catch (e: Exception) {
                            if (BuildConfig.DEBUG) Log.e("AppPermissions", "Revoke failed: ${e::class.simpleName}")
                            onDismissDialog()
                            Toast.makeText(context, toastRevokeFailed, Toast.LENGTH_SHORT).show()
                        }
                    }
                },
                colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
            ) {
                Text(stringResource(R.string.connections_app_disconnect_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismissDialog) {
                Text(stringResource(R.string.connections_app_cancel))
            }
        }
    )
}

@Composable
private fun AppPermissionsListContent(
    padding: PaddingValues,
    packageName: String,
    appState: AppState,
    appSettings: Nip55AppSettings?,
    expiryDropdownExpanded: Boolean,
    onExpiryDropdownExpandedChange: (Boolean) -> Unit,
    signPolicyStore: SignPolicyStore?,
    permissionStore: PermissionStore,
    coroutineScope: CoroutineScope,
    onAppStateChange: (AppState) -> Unit,
    onAppSettingsChange: (Nip55AppSettings?) -> Unit,
    onShowRevokeAllDialog: () -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val toastSignPolicyError = stringResource(R.string.connections_app_sign_policy_update_error)
    val errUpdatePermission = stringResource(R.string.connections_app_permission_update_error)
    val toastRevokePermissionError = stringResource(R.string.connections_app_permission_revoke_error)

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
                isVerified = appState.isVerified,
                isNip46Client = appState.isNip46Client
            )
        }

        item {
            AppExpirySelector(
                currentExpiry = appSettings?.expiresAt,
                expanded = expiryDropdownExpanded,
                onExpandedChange = onExpiryDropdownExpandedChange,
                onDurationSelected = { duration ->
                    coroutineScope.launch {
                        withContext(Dispatchers.IO) {
                            permissionStore.setAppExpiry(packageName, duration)
                        }
                        onAppSettingsChange(
                            withContext(Dispatchers.IO) {
                                permissionStore.getAppSettings(packageName)
                            }
                        )
                    }
                }
            )
        }

        if (signPolicyStore != null && !appState.isLoading) {
            item {
                KeepCard(contentPadding = PaddingValues(0.dp)) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        AppSignPolicySelector(
                            currentOverride = appState.signPolicyOverride,
                            globalPolicy = signPolicyStore.globalPolicy().toSignPolicy(),
                            onOverrideChange = { newOverride ->
                                coroutineScope.launch {
                                    try {
                                        withContext(Dispatchers.IO) {
                                            permissionStore.setAppSignPolicyOverride(packageName, newOverride)
                                        }
                                        onAppStateChange(appState.copy(signPolicyOverride = newOverride))
                                    } catch (e: Exception) {
                                        if (BuildConfig.DEBUG) Log.e("AppPermissions", "Failed to update sign policy", e)
                                        Toast.makeText(context, toastSignPolicyError, Toast.LENGTH_SHORT).show()
                                    }
                                }
                            }
                        )
                    }
                }
            }
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
                    stringResource(R.string.connections_app_no_active_permissions),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            item {
                Text(
                    stringResource(R.string.connections_app_permissions_header),
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
                                onAppStateChange(appState.copy(permissions = newPermissions))
                                updateError = null
                            } catch (e: Exception) {
                                if (BuildConfig.DEBUG) Log.e("AppPermissions", "Failed to update permission", e)
                                updateError = errUpdatePermission
                            }
                        }
                    },
                    errorMessage = updateError,
                    onRevoke = {
                        coroutineScope.launch {
                            try {
                                withContext(Dispatchers.IO) {
                                    permissionStore.deletePermission(permission.id)
                                }
                                val newPermissions = withContext(Dispatchers.IO) {
                                    permissionStore.getPermissionsForCaller(packageName)
                                }
                                onAppStateChange(appState.copy(permissions = newPermissions))
                                if (newPermissions.isEmpty()) onDismiss()
                            } catch (e: Exception) {
                                if (BuildConfig.DEBUG) Log.e("AppPermissions", "Failed to revoke permission", e)
                                Toast.makeText(context, toastRevokePermissionError, Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                )
            }
        }

        item {
            Spacer(modifier = Modifier.height(8.dp))
            Button(
                onClick = onShowRevokeAllDialog,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            ) {
                Text(if (packageName.startsWith("nip46:")) stringResource(R.string.connections_app_disconnect_client_button) else stringResource(R.string.connections_app_disconnect_app_button))
            }
        }
    }
}

private suspend fun revokeNip46Client(context: android.content.Context, pubkey: String) {
    runCatching { Nip46ClientStore.addToDenylist(context, pubkey) }
        .onFailure { if (BuildConfig.DEBUG) Log.e("AppPermissions", "Failed to denylist NIP-46 client: ${it::class.simpleName}") }
    runCatching { Nip46ClientStore.removeClient(context, pubkey) }
        .onFailure { if (BuildConfig.DEBUG) Log.e("AppPermissions", "Failed to remove NIP-46 client: ${it::class.simpleName}") }
    runCatching {
        val mobile = (context.applicationContext as? KeepMobileApp)?.getKeepMobile()
        if (mobile != null) {
            BunkerConfigStore.update(mobile) { config ->
                BunkerConfigInfo(config.enabled, config.authorizedClients.filter { it.lowercase() != pubkey.lowercase() })
            }
        }
    }.onFailure { if (BuildConfig.DEBUG) Log.e("AppPermissions", "Failed to revoke bunker client: ${it::class.simpleName}") }
    BunkerService.forgetPendingAuth(pubkey)
}

@Composable
private fun AppHeaderCard(
    packageName: String,
    appLabel: String?,
    appIcon: Drawable?,
    isVerified: Boolean,
    isNip46Client: Boolean = false
) {
    KeepCard(contentPadding = PaddingValues(0.dp)) {
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
                    if (isNip46Client) {
                        Icon(
                            Icons.Default.Cloud,
                            contentDescription = stringResource(R.string.connections_app_nip46_client_cd),
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(48.dp)
                        )
                    } else if (!isVerified) {
                        Icon(
                            Icons.Default.Warning,
                            contentDescription = stringResource(R.string.connections_app_unverified_cd),
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
                if (isNip46Client) {
                    val pubkey = packageName.removePrefix("nip46:")
                    Text(
                        text = stringResource(R.string.connections_app_nip46_client_with_pubkey, io.privkey.keep.uniffi.truncateStr(pubkey, 8u, 6u)),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                } else if (appLabel != null) {
                    Text(
                        text = packageName,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (!isVerified && !isNip46Client) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer
                        )
                    ) {
                        Text(
                            text = stringResource(R.string.connections_app_unverified_warning),
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
    val context = LocalContext.current

    KeepCard(contentPadding = PaddingValues(0.dp)) {
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
                    permission.eventKindOrNull?.let { kind ->
                        Text(
                            text = EventKind.displayName(context, kind),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    val expiryText = permission.expiresAt?.let { stringResource(R.string.connections_app_permission_expires, formatExpiry(it)) } ?: stringResource(R.string.connections_app_permission_permanent)
                    Text(
                        text = expiryText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                IconButton(onClick = onRevoke) {
                    Icon(
                        Icons.Default.Delete,
                        contentDescription = stringResource(R.string.connections_app_permission_revoke_cd),
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppExpirySelector(
    currentExpiry: Long?,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    onDurationSelected: (AppExpiryDuration) -> Unit
) {
    val displayValue = if (currentExpiry == null) {
        stringResource(R.string.app_expiry_never)
    } else {
        formatExpiry(currentExpiry)
    }

    KeepCard(contentPadding = PaddingValues(0.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(R.string.app_expiry_label),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            ExposedDropdownMenuBox(
                expanded = expanded,
                onExpandedChange = onExpandedChange
            ) {
                OutlinedTextField(
                    value = displayValue,
                    onValueChange = {},
                    readOnly = true,
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                    modifier = Modifier.fillMaxWidth().menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable)
                )
                ExposedDropdownMenu(
                    expanded = expanded,
                    onDismissRequest = { onExpandedChange(false) }
                ) {
                    AppExpiryDuration.entries.forEach { duration ->
                        DropdownMenuItem(
                            text = { Text(stringResource(duration.displayNameRes)) },
                            onClick = {
                                onDurationSelected(duration)
                                onExpandedChange(false)
                            }
                        )
                    }
                }
            }
        }
    }
}
