package io.privkey.keep.approver

import android.os.SystemClock
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.privkey.keep.QrScannerScreen
import io.privkey.keep.R
import io.privkey.keep.setSecureScreen
import io.privkey.keep.ui.components.KeepScreenScaffold
import io.privkey.keep.uniffi.ApprovalField
import io.privkey.keep.uniffi.ApproverStatus
import io.privkey.keep.uniffi.PairingStart
import java.security.Signature
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private const val PAIRING_URI_PREFIX = "keep-approver:v1?"

/** Unlocks a Signature with a strong biometric prompt titled and subtitled as given. */
typealias ApproverAuthenticator = suspend (Signature, String, String) -> Signature?

/** Confirms the owner is present (strong biometric or the device credential), titled as given. */
typealias OwnerConfirmation = suspend (String) -> Boolean

@Composable
fun ApproverScreen(
    controller: ApproverController,
    authenticate: ApproverAuthenticator,
    confirmOwner: OwnerConfirmation,
    backgroundServiceEnabled: Boolean,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    // Requests can carry what an agent would get, a NIP-44 plaintext holding money included.
    DisposableEffect(context) {
        setSecureScreen(context, true)
        onDispose { setSecureScreen(context, false) }
    }
    val scope = rememberCoroutineScope()
    val state by controller.state.collectAsState()
    var scanning by remember { mutableStateOf(false) }
    var begun by remember { mutableStateOf<PairingStart?>(null) }
    var busy by remember { mutableStateOf(false) }
    var confirmForget by remember { mutableStateOf(false) }
    val defaultLabel = stringResource(R.string.approver_default_label)
    val promptSubtitle = stringResource(R.string.approver_biometric_subtitle)
    val pairTitle = stringResource(R.string.approver_biometric_pair)
    val unfreezeTitle = stringResource(R.string.approver_biometric_unfreeze)
    val approveTitle = stringResource(R.string.approver_biometric_approve)
    val denyTitle = stringResource(R.string.approver_biometric_deny)
    val forgetAuthTitle = stringResource(R.string.approver_forget_auth)
    val acknowledgeAuthTitle = stringResource(R.string.approver_alerts_acknowledge)
    var label by remember { mutableStateOf(defaultLabel) }
    var now by remember { mutableLongStateOf(SystemClock.elapsedRealtime()) }

    LaunchedEffect(Unit) {
        controller.notices.collect { Toast.makeText(context, it, Toast.LENGTH_LONG).show() }
    }
    LaunchedEffect(Unit) {
        while (true) {
            now = SystemClock.elapsedRealtime()
            delay(1000)
        }
    }

    fun run(action: suspend () -> Unit) {
        if (busy) return
        busy = true
        scope.launch {
            try {
                action()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Toast.makeText(context, ApproverController.errorText(context, e), Toast.LENGTH_LONG).show()
            } finally {
                busy = false
            }
        }
    }

    // Never gated on busy: stopping an agent must not wait behind a prompt or another call.
    fun freeze(credentialId: String?) {
        scope.launch {
            try {
                controller.freeze(credentialId)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Toast.makeText(context, ApproverController.errorText(context, e), Toast.LENGTH_LONG).show()
            }
        }
    }

    suspend fun sign(digest: ByteArray, title: String, subtitle: String = promptSubtitle): ByteArray? =
        controller.sign(digest) { authenticate(it, title, subtitle) }

    if (scanning) {
        BackHandler { scanning = false }
        QrScannerScreen(
            onCodeScanned = { uri ->
                scanning = false
                run { begun = controller.beginPairing(uri, label.trim()) }
            },
            onDismiss = { scanning = false },
            validator = { it.startsWith(PAIRING_URI_PREFIX) },
            title = stringResource(R.string.approver_scan_title)
        )
        return
    }

    BackHandler(onBack = onDismiss)
    KeepScreenScaffold(title = stringResource(R.string.approver_title), onBack = onDismiss) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            val status = state.status
            val pending = begun
            when {
                pending != null -> PairingConfirm(
                    start = pending,
                    busy = busy,
                    onConfirm = {
                        run {
                            val signature = sign(pending.digest, pairTitle)
                                ?: return@run
                            controller.finishPairing(signature)
                            begun = null
                        }
                    },
                    onCancel = { begun = null }
                )
                status == null || (!status.paired && !status.pairing) -> Unpaired(
                    label = label,
                    onLabelChange = { label = it },
                    busy = busy,
                    onScan = { scanning = true }
                )
                else -> {
                    if (!status.running) {
                        NotRunning(state.startError ?: status.lastError, busy, onRetry = { run { controller.retryStart() } })
                    } else {
                        status.lastError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    }
                    if (!backgroundServiceEnabled) {
                        Text(stringResource(R.string.approver_background_off), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            if (status != null && status.pairing && pending == null) {
                PairingWaiting(status, busy, onCancel = { run { controller.forget() } })
            } else if (status != null && status.paired && pending == null) {
                FreezeControls(
                    status = status,
                    busy = busy,
                    onFreezeAll = { freeze(null) },
                    onUnfreeze = { credential ->
                        run {
                            val digest = controller.unfreezeDigest(credential)
                            val signature = sign(digest, unfreezeTitle)
                                ?: return@run
                            controller.sendUnfreeze(credential, signature)
                        }
                    }
                )
                Alerts(status, busy, onAcknowledge = { seq ->
                    run { if (confirmOwner(acknowledgeAuthTitle)) controller.acknowledgeAlerts(seq) }
                })
                if (state.requests.isEmpty()) {
                    Text(
                        stringResource(R.string.approver_no_requests),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                state.requests.forEach { waiting ->
                    RequestCard(
                        waiting = waiting,
                        secondsLeft = waiting.secondsLeft(now),
                        busy = busy,
                        onFreeze = { credentialId -> freeze(credentialId) },
                        onDecide = { approve ->
                            run {
                                val id = waiting.request.requestId
                                val digest = controller.decisionDigest(id, approve)
                                val subtitle = listOfNotNull(waiting.request.op, waiting.request.credential)
                                    .joinToString(" · ")
                                val signature = sign(digest, if (approve) approveTitle else denyTitle, subtitle)
                                    ?: return@run
                                controller.sendDecision(id, approve, signature)
                            }
                        }
                    )
                }
                PairingInfo(status)
                OutlinedButton(
                    onClick = { confirmForget = true },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth()
                ) { Text(stringResource(R.string.approver_forget)) }
            }
        }
    }

    if (confirmForget) {
        AlertDialog(
            onDismissRequest = { confirmForget = false },
            title = { Text(stringResource(R.string.approver_forget)) },
            text = { Text(stringResource(R.string.approver_forget_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmForget = false
                    run { if (confirmOwner(forgetAuthTitle)) controller.forget() }
                }) { Text(stringResource(R.string.approver_forget_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmForget = false }) { Text(stringResource(R.string.common_cancel)) }
            }
        )
    }
}

@Composable
fun ApproverResetDialog(onDismiss: () -> Unit, onReset: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.approver_reset_title)) },
        text = { Text(stringResource(R.string.approver_reset_body)) },
        confirmButton = {
            TextButton(onClick = onReset) { Text(stringResource(R.string.approver_reset_confirm)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_cancel)) }
        }
    )
}

@Composable
private fun Unpaired(label: String, onLabelChange: (String) -> Unit, busy: Boolean, onScan: () -> Unit) {
    Text(stringResource(R.string.approver_unpaired_body), style = MaterialTheme.typography.bodyMedium)
    OutlinedTextField(
        value = label,
        onValueChange = { if (it.length <= 64) onLabelChange(it) },
        label = { Text(stringResource(R.string.approver_label)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth()
    )
    Button(onClick = onScan, enabled = !busy && label.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.approver_scan))
    }
}

@Composable
private fun PairingConfirm(start: PairingStart, busy: Boolean, onConfirm: () -> Unit, onCancel: () -> Unit) {
    Text(stringResource(R.string.approver_fingerprint_body), style = MaterialTheme.typography.bodyMedium)
    Fingerprint(start.fingerprint)
    Button(onClick = onConfirm, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.approver_pair_sign))
    }
    OutlinedButton(onClick = onCancel, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.common_cancel))
    }
}

@Composable
private fun PairingWaiting(status: ApproverStatus, busy: Boolean, onCancel: () -> Unit) {
    Text(stringResource(R.string.approver_pairing_waiting), style = MaterialTheme.typography.bodyMedium)
    status.fingerprint?.let { Fingerprint(it) }
    OutlinedButton(onClick = onCancel, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.approver_pairing_cancel))
    }
}

@Composable
private fun NotRunning(error: String?, busy: Boolean, onRetry: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.approver_not_running), color = MaterialTheme.colorScheme.onErrorContainer)
            error?.let { Text(it, color = MaterialTheme.colorScheme.onErrorContainer) }
            TextButton(onClick = onRetry, enabled = !busy) { Text(stringResource(R.string.approver_retry)) }
        }
    }
}

@Composable
private fun Fingerprint(fingerprint: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Text(
            fingerprint,
            style = MaterialTheme.typography.headlineSmall,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.padding(16.dp)
        )
    }
}

@Composable
private fun FreezeControls(
    status: ApproverStatus,
    busy: Boolean,
    onFreezeAll: () -> Unit,
    onUnfreeze: (String?) -> Unit,
) {
    Button(
        onClick = onFreezeAll,
        modifier = Modifier.fillMaxWidth(),
        colors = ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.error,
            contentColor = MaterialTheme.colorScheme.onError
        )
    ) { Text(stringResource(R.string.approver_freeze_all)) }
    if (status.allFrozen) {
        Text(stringResource(R.string.approver_all_frozen), color = MaterialTheme.colorScheme.error)
        OutlinedButton(onClick = { onUnfreeze(null) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.approver_unfreeze_all))
        }
    }
    status.frozenCredentials.forEach { id ->
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(
                stringResource(R.string.approver_credential_frozen, id),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.weight(1f)
            )
            TextButton(onClick = { onUnfreeze(id) }, enabled = !busy) {
                Text(stringResource(R.string.approver_unfreeze))
            }
        }
    }
    if (status.silent) {
        Text(stringResource(R.string.approver_silent), color = MaterialTheme.colorScheme.error)
    }
}

@Composable
private fun Alerts(status: ApproverStatus, busy: Boolean, onAcknowledge: (ULong) -> Unit) {
    val last = status.alerts.lastOrNull() ?: return
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                stringResource(R.string.approver_alerts_title),
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            status.alerts.forEach { Text(it.message, color = MaterialTheme.colorScheme.onErrorContainer) }
            if (status.alertsDropped > 0u) {
                Text(
                    stringResource(R.string.approver_alerts_dropped, status.alertsDropped.toLong()),
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
            TextButton(onClick = { onAcknowledge(last.seq) }, enabled = !busy) {
                Text(stringResource(R.string.approver_alerts_acknowledge))
            }
        }
    }
}

@Composable
private fun RequestCard(
    waiting: WaitingRequest,
    secondsLeft: Long,
    busy: Boolean,
    onFreeze: (String) -> Unit,
    onDecide: (Boolean) -> Unit,
) {
    val request = waiting.request
    val expired = secondsLeft <= 0
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(request.op, style = MaterialTheme.typography.titleMedium)
            Text(request.reason, style = MaterialTheme.typography.bodyMedium)
            request.credential?.let {
                Text(stringResource(R.string.approver_request_credential, it), style = MaterialTheme.typography.bodyMedium)
            }
            Text(
                if (expired) stringResource(R.string.approver_request_expired)
                else stringResource(R.string.approver_request_seconds_left, secondsLeft),
                color = if (secondsLeft <= 15) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                fontWeight = FontWeight.Bold
            )
            request.warnings.forEach { Text(it, color = MaterialTheme.colorScheme.error, fontWeight = FontWeight.Bold) }
            request.fields.filterNot { it.byAgent }.forEach { FieldRow(it) }
            val agentFields = request.fields.filter { it.byAgent }
            if (agentFields.isNotEmpty()) {
                OutlinedCard(
                    border = BorderStroke(2.dp, MaterialTheme.colorScheme.tertiary),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            stringResource(R.string.approver_written_by_agent),
                            color = MaterialTheme.colorScheme.tertiary,
                            fontWeight = FontWeight.Bold
                        )
                        agentFields.forEach { FieldRow(it) }
                    }
                }
            }
            Spacer(modifier = Modifier.height(4.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(onClick = { onDecide(false) }, enabled = !busy && !expired, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.approver_deny))
                }
                Button(onClick = { onDecide(true) }, enabled = !busy && !expired, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.approver_approve))
                }
            }
            request.credentialId?.let { id ->
                OutlinedButton(
                    onClick = { onFreeze(id) },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
                ) { Text(stringResource(R.string.approver_freeze_agent)) }
            }
        }
    }
}

@Composable
private fun FieldRow(field: ApprovalField) {
    Column {
        Text(field.label, style = MaterialTheme.typography.labelMedium)
        Text(field.value, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
        if (field.removed > 0u) {
            Text(
                stringResource(R.string.approver_field_removed, field.removed.toInt()),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        }
        if (field.truncated) {
            Text(
                stringResource(R.string.approver_field_truncated, field.chars.toInt()),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        }
    }
}

@Composable
private fun PairingInfo(status: ApproverStatus) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            status.label?.let { Text(it, style = MaterialTheme.typography.titleMedium) }
            status.fingerprint?.let {
                Text(stringResource(R.string.approver_fingerprint, it), fontFamily = FontFamily.Monospace)
            }
            status.relays.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            status.epoch?.let { Text(stringResource(R.string.approver_epoch, it.toLong())) }
        }
    }
}
