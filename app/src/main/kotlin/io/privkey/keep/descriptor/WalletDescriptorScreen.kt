package io.privkey.keep.descriptor

import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.privkey.keep.copySensitiveText
import io.privkey.keep.setSecureScreen
import io.privkey.keep.uniffi.DescriptorCallbacks
import io.privkey.keep.uniffi.DescriptorProposal
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.RecoveryTierConfig
import io.privkey.keep.uniffi.WalletDescriptorInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private object ExportFormat {
    const val SPARROW = "sparrow"
    const val RAW = "raw"
}

sealed class DescriptorSessionState {
    data object Idle : DescriptorSessionState()
    data class Proposed(val sessionId: String) : DescriptorSessionState()
    data class ContributionNeeded(val proposal: DescriptorProposal) : DescriptorSessionState()
    data class Contributed(val sessionId: String, val shareIndex: UShort) : DescriptorSessionState()
    data class Complete(
        val sessionId: String,
        val externalDescriptor: String,
        val internalDescriptor: String
    ) : DescriptorSessionState()
    data class Failed(val sessionId: String, val error: String) : DescriptorSessionState()
}

object DescriptorSessionManager {
    private val _state = MutableStateFlow<DescriptorSessionState>(DescriptorSessionState.Idle)
    val state: StateFlow<DescriptorSessionState> = _state.asStateFlow()

    private val _pendingProposals = MutableStateFlow<List<DescriptorProposal>>(emptyList())
    val pendingProposals: StateFlow<List<DescriptorProposal>> = _pendingProposals.asStateFlow()

    fun createCallbacks(): DescriptorCallbacks = object : DescriptorCallbacks {
        override fun onProposed(sessionId: String) {
            _state.value = DescriptorSessionState.Proposed(sessionId)
        }

        override fun onContributionNeeded(proposal: DescriptorProposal) {
            _pendingProposals.update { it + proposal }
            _state.value = DescriptorSessionState.ContributionNeeded(proposal)
        }

        override fun onContributed(sessionId: String, shareIndex: UShort) {
            _state.value = DescriptorSessionState.Contributed(sessionId, shareIndex)
        }

        override fun onComplete(
            sessionId: String,
            externalDescriptor: String,
            internalDescriptor: String
        ) {
            _pendingProposals.update { it.filter { p -> p.sessionId != sessionId } }
            _state.value = DescriptorSessionState.Complete(sessionId, externalDescriptor, internalDescriptor)
        }

        override fun onFailed(sessionId: String, error: String) {
            _pendingProposals.update { it.filter { p -> p.sessionId != sessionId } }
            _state.value = DescriptorSessionState.Failed(sessionId, error)
        }
    }

    fun clearSessionState() {
        _state.value = DescriptorSessionState.Idle
    }

    fun clearAll() {
        _state.value = DescriptorSessionState.Idle
        _pendingProposals.value = emptyList()
    }

    fun removePendingProposal(sessionId: String) {
        _pendingProposals.update { it.filter { p -> p.sessionId != sessionId } }
    }
}

@Composable
fun WalletDescriptorScreen(
    keepMobile: KeepMobile,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var descriptors by remember { mutableStateOf<List<WalletDescriptorInfo>>(emptyList()) }
    var showProposeDialog by remember { mutableStateOf(false) }
    var showExportDialog by remember { mutableStateOf<WalletDescriptorInfo?>(null) }
    var showDeleteConfirm by remember { mutableStateOf<WalletDescriptorInfo?>(null) }
    val sessionState by DescriptorSessionManager.state.collectAsState()
    val pendingProposals by DescriptorSessionManager.pendingProposals.collectAsState()

    fun refreshDescriptors() {
        scope.launch {
            descriptors = withContext(Dispatchers.IO) { keepMobile.walletDescriptorList() }
        }
    }

    LaunchedEffect(Unit) {
        refreshDescriptors()
    }

    LaunchedEffect(sessionState) {
        if (sessionState is DescriptorSessionState.Complete) {
            refreshDescriptors()
        }
    }

    DisposableEffect(Unit) {
        setSecureScreen(context, true)
        onDispose {
            setSecureScreen(context, false)
            DescriptorSessionManager.clearSessionState()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Wallet Descriptors", style = MaterialTheme.typography.headlineMedium)
        Spacer(modifier = Modifier.height(16.dp))

        SessionStatusCard(sessionState)

        if (pendingProposals.isNotEmpty()) {
            Spacer(modifier = Modifier.height(16.dp))
            PendingContributionsCard(
                proposals = pendingProposals,
                onApprove = { proposal ->
                    scope.launch {
                        runCatching {
                            withContext(Dispatchers.IO) {
                                keepMobile.walletDescriptorApproveContribution(proposal.sessionId)
                            }
                            DescriptorSessionManager.removePendingProposal(proposal.sessionId)
                        }.onFailure {
                            Toast.makeText(context, "Failed to approve", Toast.LENGTH_SHORT).show()
                        }
                    }
                },
                onReject = { proposal ->
                    scope.launch {
                        runCatching {
                            withContext(Dispatchers.IO) {
                                keepMobile.walletDescriptorCancel(proposal.sessionId)
                            }
                            DescriptorSessionManager.removePendingProposal(proposal.sessionId)
                        }.onFailure {
                            Toast.makeText(context, "Failed to reject", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = { showProposeDialog = true },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("New Descriptor")
        }

        Spacer(modifier = Modifier.height(16.dp))

        DescriptorListCard(
            descriptors = descriptors,
            onExport = { showExportDialog = it },
            onDelete = { showDeleteConfirm = it }
        )

        Spacer(modifier = Modifier.height(24.dp))

        TextButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
            Text("Back")
        }
    }

    if (showProposeDialog) {
        ProposeDescriptorDialog(
            onPropose = { network, tiers ->
                scope.launch {
                    runCatching {
                        withContext(Dispatchers.IO) {
                            keepMobile.walletDescriptorPropose(network, tiers)
                        }
                    }.onFailure {
                        Toast.makeText(context, "Failed to propose descriptor", Toast.LENGTH_SHORT).show()
                    }
                    showProposeDialog = false
                }
            },
            onDismiss = { showProposeDialog = false }
        )
    }

    showExportDialog?.let { descriptor ->
        ExportDescriptorDialog(
            descriptor = descriptor,
            onExport = { format ->
                scope.launch {
                    runCatching {
                        val exported = withContext(Dispatchers.IO) {
                            keepMobile.walletDescriptorExport(descriptor.groupPubkey, format)
                        }
                        copySensitiveText(context, exported)
                        Toast.makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT).show()
                    }.onFailure {
                        Toast.makeText(context, "Export failed", Toast.LENGTH_SHORT).show()
                    }
                    showExportDialog = null
                }
            },
            onDismiss = { showExportDialog = null }
        )
    }

    showDeleteConfirm?.let { descriptor ->
        DeleteDescriptorDialog(
            descriptor = descriptor,
            onConfirm = {
                scope.launch {
                    runCatching {
                        withContext(Dispatchers.IO) {
                            keepMobile.walletDescriptorDelete(descriptor.groupPubkey)
                        }
                        refreshDescriptors()
                    }.onFailure {
                        Toast.makeText(context, "Delete failed", Toast.LENGTH_SHORT).show()
                    }
                    showDeleteConfirm = null
                }
            },
            onDismiss = { showDeleteConfirm = null }
        )
    }
}

@Composable
private fun SessionStatusCard(state: DescriptorSessionState) {
    if (state is DescriptorSessionState.Idle) return

    val (statusText, statusColor) = when (state) {
        is DescriptorSessionState.Proposed -> "Proposed — waiting for contributions" to MaterialTheme.colorScheme.primary
        is DescriptorSessionState.ContributionNeeded -> "Contribution needed" to MaterialTheme.colorScheme.tertiary
        is DescriptorSessionState.Contributed -> "Share ${state.shareIndex} contributed" to MaterialTheme.colorScheme.secondary
        is DescriptorSessionState.Complete -> "Descriptor complete" to MaterialTheme.colorScheme.primary
        is DescriptorSessionState.Failed -> "Failed: ${state.error}" to MaterialTheme.colorScheme.error
        is DescriptorSessionState.Idle -> return
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Session Status", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            Text(statusText, color = statusColor, style = MaterialTheme.typography.bodyMedium)
            if (state is DescriptorSessionState.Complete) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    "External: ${state.externalDescriptor.take(40)}...",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun PendingContributionsCard(
    proposals: List<DescriptorProposal>,
    onApprove: (DescriptorProposal) -> Unit,
    onReject: (DescriptorProposal) -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Pending Contributions", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            proposals.forEachIndexed { index, proposal ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            proposal.network,
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Text(
                            "${proposal.tiers.size} tier(s)",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { onReject(proposal) }) {
                            Text("Reject")
                        }
                        Button(onClick = { onApprove(proposal) }) {
                            Text("Approve")
                        }
                    }
                }
                if (index < proposals.lastIndex) {
                    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                }
            }
        }
    }
}

@Composable
private fun DescriptorListCard(
    descriptors: List<WalletDescriptorInfo>,
    onExport: (WalletDescriptorInfo) -> Unit,
    onDelete: (WalletDescriptorInfo) -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Descriptors (${descriptors.size})", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            if (descriptors.isEmpty()) {
                Text(
                    "No wallet descriptors",
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                descriptors.forEachIndexed { index, descriptor ->
                    DescriptorRow(descriptor, onExport, onDelete)
                    if (index < descriptors.lastIndex) {
                        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun DescriptorRow(
    descriptor: WalletDescriptorInfo,
    onExport: (WalletDescriptorInfo) -> Unit,
    onDelete: (WalletDescriptorInfo) -> Unit
) {
    val dateFormat = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()) }

    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(
            "${descriptor.groupPubkey.take(8)}...${descriptor.groupPubkey.takeLast(6)}",
            style = MaterialTheme.typography.bodyMedium
        )
        Spacer(modifier = Modifier.height(4.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                descriptor.network,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary
            )
            Text(
                dateFormat.format(Date(descriptor.createdAt.toLong() * 1000)),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(modifier = Modifier.height(8.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedButton(
                onClick = { onExport(descriptor) },
                modifier = Modifier.weight(1f)
            ) {
                Text("Export")
            }
            OutlinedButton(
                onClick = { onDelete(descriptor) },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                )
            ) {
                Text("Delete")
            }
        }
    }
}

@Composable
private fun ProposeDescriptorDialog(
    onPropose: (String, List<RecoveryTierConfig>) -> Unit,
    onDismiss: () -> Unit
) {
    var network by remember { mutableStateOf("bitcoin") }
    var threshold by remember { mutableStateOf("2") }
    var timelockMonths by remember { mutableStateOf("6") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New Wallet Descriptor") },
        text = {
            Column {
                Text("Network", style = MaterialTheme.typography.labelMedium)
                Spacer(modifier = Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("bitcoin", "testnet", "signet").forEach { net ->
                        FilterChip(
                            selected = network == net,
                            onClick = { network = net },
                            label = { Text(net) }
                        )
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
                Text("Recovery Tier", style = MaterialTheme.typography.labelMedium)
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = threshold,
                    onValueChange = { threshold = it.filter { c -> c.isDigit() } },
                    label = { Text("Threshold") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = timelockMonths,
                    onValueChange = { timelockMonths = it.filter { c -> c.isDigit() } },
                    label = { Text("Timelock (months)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val t = threshold.toUIntOrNull() ?: return@TextButton
                    val tl = timelockMonths.toUIntOrNull() ?: return@TextButton
                    if (t < 1u || tl < 1u) return@TextButton
                    onPropose(network, listOf(RecoveryTierConfig(t, tl)))
                }
            ) {
                Text("Propose")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

@Composable
private fun ExportDescriptorDialog(
    descriptor: WalletDescriptorInfo,
    onExport: (String) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Export Descriptor") },
        text = {
            Column {
                Text(
                    "${descriptor.groupPubkey.take(8)}...${descriptor.groupPubkey.takeLast(6)}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text("Choose export format:")
            }
        },
        confirmButton = {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { onExport(ExportFormat.SPARROW) }) { Text("Sparrow") }
                TextButton(onClick = { onExport(ExportFormat.RAW) }) { Text("Raw") }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

@Composable
private fun DeleteDescriptorDialog(
    descriptor: WalletDescriptorInfo,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Delete Descriptor?") },
        text = {
            Text("This will permanently remove the wallet descriptor for ${descriptor.groupPubkey.take(8)}...${descriptor.groupPubkey.takeLast(6)}")
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm() },
                colors = ButtonDefaults.textButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                )
            ) {
                Text("Delete")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}
