package io.privkey.keep

import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Build
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import io.privkey.keep.nip55.PermissionStore
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.SigningAuditLog
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedOutputStream
import java.io.File
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private sealed class ExportLogsState {
    data object Idle : ExportLogsState()
    data object Collecting : ExportLogsState()
    data object Saving : ExportLogsState()
    data class Error(val message: String) : ExportLogsState()
}

private enum class ExportAction { Save, Share }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportLogsScreen(
    keepMobile: KeepMobile,
    storage: AndroidKeystoreStorage,
    signingAuditLog: SigningAuditLog?,
    permissionStore: PermissionStore?,
    foregroundServiceEnabled: Boolean,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf<ExportLogsState>(ExportLogsState.Idle) }
    var pendingContent by remember { mutableStateOf<String?>(null) }

    val saveFileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri ->
        val content = pendingContent
        pendingContent = null
        if (uri == null) {
            state = ExportLogsState.Idle
            return@rememberLauncherForActivityResult
        }
        if (content == null) return@rememberLauncherForActivityResult
        state = ExportLogsState.Saving
        scope.launch {
            try {
                withContext(NonCancellable + Dispatchers.IO) {
                    val outputStream = context.contentResolver.openOutputStream(uri)
                        ?: throw java.io.IOException("openOutputStream returned null")
                    BufferedOutputStream(outputStream).use { buffered ->
                        buffered.write(content.toByteArray(Charsets.UTF_8))
                        buffered.flush()
                    }
                }
                Toast.makeText(context, "Logs saved", Toast.LENGTH_SHORT).show()
                state = ExportLogsState.Idle
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.e("ExportLogs", "Failed to save logs", e)
                state = ExportLogsState.Error("Failed to save logs")
            }
        }
    }

    fun runExport(action: ExportAction) {
        state = ExportLogsState.Collecting
        scope.launch {
            try {
                val content = withContext(Dispatchers.IO) {
                    buildExportContent(
                        keepMobile = keepMobile,
                        storage = storage,
                        signingAuditLog = signingAuditLog,
                        permissionStore = permissionStore,
                        foregroundServiceEnabled = foregroundServiceEnabled
                    )
                }
                val timestamp = LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"))
                val saveName = "keep-logs-$timestamp.txt"
                when (action) {
                    ExportAction.Save -> {
                        pendingContent = content
                        saveFileLauncher.launch(saveName)
                    }
                    ExportAction.Share -> {
                        val uri = withContext(NonCancellable + Dispatchers.IO) {
                            val dir = File(context.cacheDir, "logs").apply { mkdirs() }
                            val pruneBefore = System.currentTimeMillis() - 10 * 60 * 1000L
                            dir.listFiles()?.forEach { old ->
                                if (old.lastModified() < pruneBefore) old.delete()
                            }
                            val uniqueName = "keep-logs-$timestamp-${System.nanoTime()}.txt"
                            val file = File(dir, uniqueName)
                            file.writeText(content, Charsets.UTF_8)
                            FileProvider.getUriForFile(
                                context,
                                "${context.packageName}.fileprovider",
                                file
                            )
                        }
                        val sendIntent = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_STREAM, uri)
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        val chooser = Intent.createChooser(sendIntent, "Share logs").apply {
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        try {
                            context.startActivity(chooser)
                            state = ExportLogsState.Idle
                        } catch (e: ActivityNotFoundException) {
                            if (BuildConfig.DEBUG) Log.e("ExportLogs", "No share target", e)
                            state = ExportLogsState.Error("No app available to share")
                        }
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.e("ExportLogs", "Export failed", e)
                state = ExportLogsState.Error(
                    if (action == ExportAction.Share) "Failed to share logs" else "Failed to collect logs"
                )
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Export & Share Logs") },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Diagnostic Logs", style = MaterialTheme.typography.titleMedium)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        "Collects app diagnostics into a plain text file. Includes: device " +
                            "manufacturer/model, Android version, app version and build type, " +
                            "account count, foreground service and Tor/proxy configuration, " +
                            "signing audit history (caller package names, caller display names, " +
                            "event kinds, and free-text reasons), and NIP-55 permission audit " +
                            "history. Does not include private keys, nsec, or seed words.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        "Warning: audit entries include caller display names and free-text " +
                            "reasons supplied by third-party apps. These fields may contain " +
                            "personal information or attacker-controlled content. Review the " +
                            "file before sharing.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    val isBusy = state is ExportLogsState.Collecting || state is ExportLogsState.Saving

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = { runExport(ExportAction.Save) },
                            enabled = !isBusy,
                            modifier = Modifier.weight(1f)
                        ) {
                            if (isBusy) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(16.dp),
                                    strokeWidth = 2.dp
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                            }
                            Text("Save to File")
                        }
                        Button(
                            onClick = { runExport(ExportAction.Share) },
                            enabled = !isBusy,
                            modifier = Modifier.weight(1f)
                        ) {
                            if (isBusy) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(16.dp),
                                    strokeWidth = 2.dp,
                                    color = MaterialTheme.colorScheme.onPrimary
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                            }
                            Text("Share")
                        }
                    }

                    val errorState = state as? ExportLogsState.Error
                    if (errorState != null) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            errorState.message,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

private suspend fun buildExportContent(
    keepMobile: KeepMobile,
    storage: AndroidKeystoreStorage,
    signingAuditLog: SigningAuditLog?,
    permissionStore: PermissionStore?,
    foregroundServiceEnabled: Boolean
): String {
    val accountCountDisplay = runCatching { storage.listAllShares().size }.fold(
        onSuccess = { it.toString() },
        onFailure = { "unavailable (${it::class.simpleName})" }
    )
    val proxyConfig = runCatching { keepMobile.getProxyConfig() }.getOrNull()
    val torStatus = when {
        proxyConfig == null -> "unknown"
        proxyConfig.enabled -> "enabled (port ${proxyConfig.port})"
        else -> "disabled"
    }
    val timestamp = DateTimeFormatter.ISO_OFFSET_DATE_TIME
        .withZone(ZoneId.systemDefault())
        .format(Instant.now())

    val nip55AuditResult = permissionStore?.let { store ->
        runCatching {
            val totalCount = store.getAuditLogCount()
            val entries = store.getAuditLog(limit = 1000)
            val array = JSONArray()
            for (e in entries) {
                val obj = JSONObject()
                obj.put("id", e.id)
                obj.put("timestamp", e.timestamp)
                obj.put("callerPackage", e.callerPackage)
                obj.put("requestType", e.requestType)
                obj.put("eventKind", e.eventKind ?: JSONObject.NULL)
                obj.put("decision", e.decision)
                obj.put("wasAutomatic", e.wasAutomatic)
                obj.put("previousHash", e.previousHash ?: JSONObject.NULL)
                obj.put("entryHash", e.entryHash)
                array.put(obj)
            }
            Triple(array.toString(2), entries.size, totalCount)
        }.getOrElse { e ->
            Triple("(export failed: ${e::class.simpleName})", 0, 0)
        }
    }

    return buildString {
        appendLine("=== Keep Diagnostics ===")
        appendLine("Exported: $timestamp")
        appendLine("App version: ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
        appendLine("Build type: ${BuildConfig.BUILD_TYPE}")
        appendLine("Android version: ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT})")
        appendLine("Device: ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("Account count: $accountCountDisplay")
        appendLine("Foreground service: ${if (foregroundServiceEnabled) "enabled" else "disabled"}")
        appendLine("Tor/proxy: $torStatus")
        appendLine()
        appendLine("=== Signing Audit Log ===")
        if (signingAuditLog == null) {
            appendLine("(unavailable)")
        } else {
            try {
                appendLine(signingAuditLog.exportJson())
            } catch (e: Exception) {
                val sanitized = e.message
                    ?.replace(Regex("[\\r\\n\\t]"), " ")
                    ?.take(200)
                appendLine("(export failed: ${e::class.simpleName}${if (sanitized.isNullOrBlank()) "" else ": $sanitized"})")
            }
        }
        appendLine()
        appendLine("=== NIP-55 Audit Log ===")
        if (nip55AuditResult == null) {
            appendLine("(unavailable)")
        } else {
            val (json, exported, total) = nip55AuditResult
            if (total > exported) {
                appendLine("(truncated to $exported of $total entries)")
            }
            appendLine(json)
        }
    }
}
