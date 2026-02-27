package io.privkey.keep.descriptor

import android.util.Log
import io.privkey.keep.BuildConfig
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
import io.privkey.keep.uniffi.AnnouncedXpubInfo
import io.privkey.keep.uniffi.WalletDescriptorInfo
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

private const val TAG = "WalletDescriptor"
private val XPUB_PREFIXES = listOf("xpub", "tpub", "ypub", "zpub", "upub", "vpub", "Ypub", "Zpub", "Upub", "Vpub")
private val FP_REGEX = Regex("^[0-9a-fA-F]{8}$")

private object ExportFormat {
    const val SPARROW = "sparrow"
    const val RAW = "raw"
}

private fun truncateText(text: String, maxLength: Int): String =
    if (text.length <= maxLength) text else "${text.take(maxLength)}..."

private fun truncateGroupPubkey(key: String): String =
    if (key.length <= 14) key else "${key.take(8)}...${key.takeLast(6)}"

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

    private val _callbacksRegistered = MutableStateFlow(false)
    val callbacksRegistered: StateFlow<Boolean> = _callbacksRegistered.asStateFlow()

    private val _announcedXpubs = MutableStateFlow<Map<UShort, List<AnnouncedXpubInfo>>>(emptyMap())
    val announcedXpubs: StateFlow<Map<UShort, List<AnnouncedXpubInfo>>> = _announcedXpubs.asStateFlow()

    @Volatile
    private var active = true

    fun setCallbacksRegistered(registered: Boolean) {
        _callbacksRegistered.value = registered
    }

    fun createCallbacks(): DescriptorCallbacks = object : DescriptorCallbacks {
        override fun onProposed(sessionId: String) {
            if (!active) return
            _state.value = DescriptorSessionState.Proposed(sessionId)
        }

        override fun onContributionNeeded(proposal: DescriptorProposal) {
            if (!active) return
            _pendingProposals.update { current ->
                if (current.any { it.sessionId == proposal.sessionId }) current else current + proposal
            }
            _state.value = DescriptorSessionState.ContributionNeeded(proposal)
        }

        override fun onContributed(sessionId: String, shareIndex: UShort) {
            if (!active) return
            _state.value = DescriptorSessionState.Contributed(sessionId, shareIndex)
        }

        override fun onXpubAnnounced(shareIndex: UShort, xpubs: List<AnnouncedXpubInfo>) {
            if (!active) return
            if (BuildConfig.DEBUG) Log.d(TAG, "Xpub announced for share $shareIndex: ${xpubs.size} xpub(s)")
            _announcedXpubs.update { current -> current + (shareIndex to (current[shareIndex].orEmpty() + xpubs)) }
        }

        override fun onComplete(
            sessionId: String,
            externalDescriptor: String,
            internalDescriptor: String
        ) {
            if (!active) return
            removePendingProposal(sessionId)
            _state.value = DescriptorSessionState.Complete(sessionId, externalDescriptor, internalDescriptor)
        }

        override fun onFailed(sessionId: String, error: String) {
            if (!active) return
            removePendingProposal(sessionId)
            _state.value = DescriptorSessionState.Failed(sessionId, error)
        }
    }

    fun clearSessionState() {
        _state.value = DescriptorSessionState.Idle
    }

    fun clearAll() {
        active = false
        _state.value = DescriptorSessionState.Idle
        _pendingProposals.value = emptyList()
        _announcedXpubs.value = emptyMap()
    }

    fun activate() {
        active = true
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
    var inFlightSessions by remember { mutableStateOf(emptySet<String>()) }
    var isProposing by remember { mutableStateOf(false) }
    var isExporting by remember { mutableStateOf(false) }
    var isDeleting by remember { mutableStateOf(false) }
    var showAnnounceDialog by remember { mutableStateOf(false) }
    var isAnnouncing by remember { mutableStateOf(false) }
    val sessionState by DescriptorSessionManager.state.collectAsState()
    val pendingProposals by DescriptorSessionManager.pendingProposals.collectAsState()
    val callbacksRegistered by DescriptorSessionManager.callbacksRegistered.collectAsState()
    val announcedXpubs by DescriptorSessionManager.announcedXpubs.collectAsState()

    fun refreshDescriptors() {
        scope.launch {
            runCatching {
                withContext(Dispatchers.IO) { keepMobile.walletDescriptorList() }
            }.onSuccess {
                descriptors = it
            }.onFailure {
                if (it is CancellationException) throw it
                Toast.makeText(context, "Failed to load descriptors", Toast.LENGTH_SHORT).show()
            }
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
        DescriptorSessionManager.activate()
        onDispose {
            setSecureScreen(context, false)
            DescriptorSessionManager.clearAll()
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

        if (!callbacksRegistered) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer
                )
            ) {
                Text(
                    "Real-time updates unavailable. Propose and list operations still work.",
                    modifier = Modifier.padding(16.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    style = MaterialTheme.typography.bodySmall
                )
            }
            Spacer(modifier = Modifier.height(16.dp))
        }

        SessionStatusCard(sessionState)

        fun handleProposalAction(
            proposal: DescriptorProposal,
            action: String,
            block: suspend (String) -> Unit
        ) {
            if (proposal.sessionId in inFlightSessions) return
            inFlightSessions = inFlightSessions + proposal.sessionId
            scope.launch {
                runCatching {
                    withContext(Dispatchers.IO) { block(proposal.sessionId) }
                }.onSuccess {
                    DescriptorSessionManager.removePendingProposal(proposal.sessionId)
                }.onFailure { e ->
                    if (e is CancellationException) throw e
                    Log.w(TAG, "Failed to $action contribution: ${e.javaClass.simpleName}")
                    Toast.makeText(context, "Failed to $action contribution", Toast.LENGTH_LONG).show()
                }
                inFlightSessions = inFlightSessions - proposal.sessionId
            }
        }

        if (pendingProposals.isNotEmpty()) {
            Spacer(modifier = Modifier.height(16.dp))

            PendingContributionsCard(
                proposals = pendingProposals,
                inFlightSessions = inFlightSessions,
                onApprove = { handleProposalAction(it, "approve") { id ->
                    keepMobile.walletDescriptorApproveContribution(id)
                }},
                onReject = { handleProposalAction(it, "reject") { id ->
                    keepMobile.walletDescriptorCancel(id)
                }}
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = { showProposeDialog = true },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("New Descriptor")
        }

        Spacer(modifier = Modifier.height(8.dp))

        Button(
            onClick = { showAnnounceDialog = true },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.secondary
            )
        ) {
            Text("Announce Recovery Keys")
        }

        if (announcedXpubs.isNotEmpty()) {
            Spacer(modifier = Modifier.height(16.dp))
            AnnouncedXpubsCard(announcedXpubs)
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
            isProposing = isProposing,
            onPropose = { network, tiers ->
                if (isProposing) return@ProposeDescriptorDialog
                isProposing = true
                scope.launch {
                    try {
                        runCatching {
                            withContext(Dispatchers.IO) {
                                keepMobile.walletDescriptorPropose(network, tiers)
                            }
                        }.onSuccess {
                            showProposeDialog = false
                        }.onFailure { e ->
                            if (e is CancellationException) throw e
                            Log.w(TAG, "Failed to propose descriptor: ${e.javaClass.simpleName}")
                            Toast.makeText(context, "Failed to propose descriptor", Toast.LENGTH_LONG).show()
                        }
                    } finally {
                        isProposing = false
                    }
                }
            },
            onDismiss = { showProposeDialog = false }
        )
    }

    showExportDialog?.let { descriptor ->
        ExportDescriptorDialog(
            descriptor = descriptor,
            isExporting = isExporting,
            onExport = { format ->
                if (isExporting) return@ExportDescriptorDialog
                isExporting = true
                scope.launch {
                    try {
                        runCatching {
                            val exported = withContext(Dispatchers.IO) {
                                keepMobile.walletDescriptorExport(descriptor.groupPubkey, format)
                            }
                            copySensitiveText(context, exported)
                            Toast.makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT).show()
                        }.onFailure { e ->
                            if (e is CancellationException) throw e
                            Log.w(TAG, "Failed to export descriptor: ${e.javaClass.simpleName}")
                            Toast.makeText(context, "Export failed", Toast.LENGTH_LONG).show()
                        }
                    } finally {
                        isExporting = false
                        showExportDialog = null
                    }
                }
            },
            onDismiss = { showExportDialog = null }
        )
    }

    showDeleteConfirm?.let { descriptor ->
        DeleteDescriptorDialog(
            descriptor = descriptor,
            isDeleting = isDeleting,
            onConfirm = {
                if (isDeleting) return@DeleteDescriptorDialog
                isDeleting = true
                scope.launch {
                    try {
                        runCatching {
                            withContext(Dispatchers.IO) {
                                keepMobile.walletDescriptorDelete(descriptor.groupPubkey)
                            }
                        }.onSuccess {
                            showDeleteConfirm = null
                            refreshDescriptors()
                        }.onFailure { e ->
                            if (e is CancellationException) throw e
                            Log.w(TAG, "Failed to delete descriptor: ${e.javaClass.simpleName}")
                            Toast.makeText(context, "Delete failed", Toast.LENGTH_LONG).show()
                        }
                    } finally {
                        isDeleting = false
                    }
                }
            },
            onDismiss = { showDeleteConfirm = null }
        )
    }

    if (showAnnounceDialog) {
        AnnounceXpubsDialog(
            isAnnouncing = isAnnouncing,
            onAnnounce = { xpub, fingerprint, label ->
                if (isAnnouncing) return@AnnounceXpubsDialog
                isAnnouncing = true
                scope.launch {
                    try {
                        runCatching {
                            withContext(Dispatchers.IO) {
                                keepMobile.walletAnnounceXpubs(
                                    listOf(AnnouncedXpubInfo(xpub, fingerprint, label.ifBlank { null }))
                                )
                            }
                        }.onSuccess {
                            showAnnounceDialog = false
                        }.onFailure { e ->
                            if (e is CancellationException) throw e
                            Log.w(TAG, "Failed to announce xpubs: ${e.javaClass.simpleName}")
                            Toast.makeText(context, "Failed to announce recovery keys", Toast.LENGTH_LONG).show()
                        }
                    } finally {
                        isAnnouncing = false
                    }
                }
            },
            onDismiss = { showAnnounceDialog = false }
        )
    }
}

@Composable
private fun SessionStatusCard(state: DescriptorSessionState) {
    val (statusText, statusColor) = when (state) {
        is DescriptorSessionState.Proposed -> "Proposed — waiting for contributions" to MaterialTheme.colorScheme.primary
        is DescriptorSessionState.ContributionNeeded -> "Contribution needed" to MaterialTheme.colorScheme.tertiary
        is DescriptorSessionState.Contributed -> "Share ${state.shareIndex} contributed" to MaterialTheme.colorScheme.secondary
        is DescriptorSessionState.Complete -> "Descriptor complete" to MaterialTheme.colorScheme.primary
        is DescriptorSessionState.Failed -> (if (BuildConfig.DEBUG) "Failed: ${truncateText(state.error, 80)}" else "Operation failed") to MaterialTheme.colorScheme.error
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
                    "External: ${truncateText(state.externalDescriptor, 40)}",
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
    inFlightSessions: Set<String>,
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
                        Text(
                            "Approval includes key control proof",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.tertiary
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        val busy = proposal.sessionId in inFlightSessions
                        OutlinedButton(onClick = { onReject(proposal) }, enabled = !busy) {
                            Text("Reject")
                        }
                        Button(onClick = { onApprove(proposal) }, enabled = !busy) {
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
    val dateFormat = remember {
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.getDefault())
            .withZone(ZoneId.systemDefault())
    }

    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(
            truncateGroupPubkey(descriptor.groupPubkey),
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
                dateFormat.format(Instant.ofEpochSecond(descriptor.createdAt.toLong())),
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
    isProposing: Boolean = false,
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
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
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
                val thresholdError = threshold.isNotEmpty() && threshold.toUIntOrNull()?.let { it !in 1u..15u } == true
                OutlinedTextField(
                    value = threshold,
                    onValueChange = { threshold = it.filter { c -> c.isDigit() } },
                    label = { Text("Threshold (1–15)") },
                    isError = thresholdError || (threshold.isEmpty()),
                    supportingText = if (threshold.isEmpty()) {
                        { Text("Required") }
                    } else if (thresholdError) {
                        { Text("Must be between 1 and 15") }
                    } else null,
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                val timelockError = timelockMonths.isNotEmpty() && timelockMonths.toUIntOrNull()?.let { it !in 1u..120u } == true
                OutlinedTextField(
                    value = timelockMonths,
                    onValueChange = { timelockMonths = it.filter { c -> c.isDigit() } },
                    label = { Text("Timelock months (1–120)") },
                    isError = timelockError || (timelockMonths.isEmpty()),
                    supportingText = if (timelockMonths.isEmpty()) {
                        { Text("Required") }
                    } else if (timelockError) {
                        { Text("Must be between 1 and 120") }
                    } else null,
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            val parsedThreshold = threshold.toUIntOrNull()
            val parsedTimelock = timelockMonths.toUIntOrNull()
            val valid = parsedThreshold in 1u..15u && parsedTimelock in 1u..120u
            TextButton(
                onClick = {
                    if (parsedThreshold != null && parsedTimelock != null) {
                        onPropose(network, listOf(RecoveryTierConfig(parsedThreshold, parsedTimelock)))
                    }
                },
                enabled = valid && !isProposing
            ) {
                Text(if (isProposing) "Proposing..." else "Propose")
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
    isExporting: Boolean = false,
    onExport: (String) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Export Descriptor") },
        text = {
            Column {
                Text(
                    truncateGroupPubkey(descriptor.groupPubkey),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(if (isExporting) "Exporting..." else "Choose export format:")
            }
        },
        confirmButton = {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { onExport(ExportFormat.SPARROW) }, enabled = !isExporting) { Text("Sparrow") }
                TextButton(onClick = { onExport(ExportFormat.RAW) }, enabled = !isExporting) { Text("Raw") }
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
    isDeleting: Boolean = false,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Delete Descriptor?") },
        text = {
            Text("This will permanently remove the wallet descriptor for ${truncateGroupPubkey(descriptor.groupPubkey)}")
        },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                enabled = !isDeleting,
                colors = ButtonDefaults.textButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                )
            ) {
                Text(if (isDeleting) "Deleting..." else "Delete")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

@Composable
private fun AnnouncedXpubsCard(announcedXpubs: Map<UShort, List<AnnouncedXpubInfo>>) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Announced Recovery Keys", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            announcedXpubs.entries.sortedBy { it.key }.forEachIndexed { index, (shareIndex, xpubs) ->
                Text(
                    "Share $shareIndex",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary
                )
                xpubs.forEach { xpub ->
                    Column(modifier = Modifier.padding(start = 8.dp, top = 4.dp)) {
                        Text(
                            truncateText(xpub.xpub, 32),
                            style = MaterialTheme.typography.bodySmall
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                "fp: ${xpub.fingerprint}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            xpub.label?.let { label ->
                                Text(
                                    label,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.secondary
                                )
                            }
                        }
                    }
                }
                if (index < announcedXpubs.size - 1) {
                    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                }
            }
        }
    }
}

@Composable
private fun AnnounceXpubsDialog(
    isAnnouncing: Boolean = false,
    onAnnounce: (String, String, String) -> Unit,
    onDismiss: () -> Unit
) {
    var xpub by remember { mutableStateOf("") }
    var fingerprint by remember { mutableStateOf("") }
    var label by remember { mutableStateOf("") }

    val trimmedXpub = xpub.trim()
    val xpubFormatError = trimmedXpub.isNotEmpty() && XPUB_PREFIXES.none { trimmedXpub.startsWith(it) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Announce Recovery Key") },
        text = {
            Column {
                OutlinedTextField(
                    value = xpub,
                    onValueChange = { xpub = it.take(200) },
                    label = { Text("Recovery xpub") },
                    isError = trimmedXpub.isEmpty() || xpubFormatError,
                    supportingText = when {
                        trimmedXpub.isEmpty() -> {{ Text("Required") }}
                        xpubFormatError -> {{ Text("Must start with a valid xpub prefix") }}
                        else -> null
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                val fpError = fingerprint.isNotEmpty() && !fingerprint.matches(FP_REGEX)
                OutlinedTextField(
                    value = fingerprint,
                    onValueChange = { fingerprint = it.filter { c -> c.isDigit() || c in 'a'..'f' || c in 'A'..'F' }.take(8) },
                    label = { Text("Fingerprint (8 hex chars)") },
                    isError = fingerprint.isEmpty() || fpError,
                    supportingText = when {
                        fingerprint.isEmpty() -> {{ Text("Required") }}
                        fpError -> {{ Text("Must be 8 hex characters") }}
                        else -> null
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it.filter { c -> !c.isISOControl() }.take(64) },
                    label = { Text("Label (optional)") },
                    placeholder = { Text("e.g. coldcard-backup") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            val valid = trimmedXpub.isNotEmpty() && !xpubFormatError && fingerprint.matches(FP_REGEX)
            TextButton(
                onClick = { onAnnounce(xpub.trim(), fingerprint, label) },
                enabled = valid && !isAnnouncing
            ) {
                Text(if (isAnnouncing) "Announcing..." else "Announce")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}
