package io.privkey.keep.descriptor

import android.util.Log
import android.widget.Toast
import io.privkey.keep.BuildConfig
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.privkey.keep.R
import io.privkey.keep.copySensitiveText
import io.privkey.keep.setSecureScreen
import io.privkey.keep.uniffi.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val TAG = "WalletDescriptor"
private const val MAX_PENDING_PROPOSALS = 50
private const val MAX_POLL_RETRIES = 60
private const val POLL_INTERVAL_MS = 5_000L
private const val MAX_POLL_INTERVAL_MS = 60_000L
private const val POLL_DEADLINE_MS = 30 * 60 * 1000L
private val XPUB_PREFIXES = listOf("xpub", "tpub", "ypub", "zpub", "upub", "vpub", "Ypub", "Zpub", "Upub", "Vpub")
private val FP_REGEX = Regex("^[0-9a-fA-F]{8}$")

private object ExportFormat {
    const val SPARROW = "sparrow"
    const val RAW = "raw"
}

private fun truncateText(text: String, maxLength: Int): String =
    if (text.length <= maxLength) text else "${text.take(maxLength)}..."

private fun truncateGroupPubkey(key: String): String =
    truncateStr(key, 8u, 6u)

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

    private val lock = Any()
    private var active = true

    fun setCallbacksRegistered(registered: Boolean) {
        synchronized(lock) {
            if (!active) return
            _callbacksRegistered.value = registered
        }
    }

    fun createCallbacks(): DescriptorCallbacks = object : DescriptorCallbacks {
        override fun onProposed(sessionId: String) {
            synchronized(lock) {
                if (!active) return
                _state.value = DescriptorSessionState.Proposed(sessionId)
            }
        }

        override fun onContributionNeeded(proposal: DescriptorProposal) {
            synchronized(lock) {
                if (!active) return
                _pendingProposals.update { current ->
                    if (current.any { it.sessionId == proposal.sessionId }) current
                    else (current + proposal).takeLast(MAX_PENDING_PROPOSALS)
                }
                _state.value = DescriptorSessionState.ContributionNeeded(proposal)
            }
        }

        override fun onContributed(sessionId: String, shareIndex: UShort) {
            synchronized(lock) {
                if (!active) return
                _state.value = DescriptorSessionState.Contributed(sessionId, shareIndex)
            }
        }

        override fun onXpubAnnounced(shareIndex: UShort, xpubs: List<AnnouncedXpubInfo>) {
            synchronized(lock) {
                if (!active) return
                if (BuildConfig.DEBUG) Log.d(TAG, "Xpub announced for share $shareIndex: ${xpubs.size} xpub(s)")
                _announcedXpubs.update { current ->
                    current + (shareIndex to (current[shareIndex].orEmpty() + xpubs).distinctBy { it.xpub })
                }
            }
        }

        override fun onComplete(
            sessionId: String,
            externalDescriptor: String,
            internalDescriptor: String
        ) {
            synchronized(lock) {
                if (!active) return
                doRemovePendingProposal(sessionId)
                _state.value = DescriptorSessionState.Complete(sessionId, externalDescriptor, internalDescriptor)
            }
        }

        override fun onFailed(sessionId: String, error: String) {
            synchronized(lock) {
                if (!active) return
                doRemovePendingProposal(sessionId)
                _state.value = DescriptorSessionState.Failed(sessionId, error)
            }
        }
    }

    fun setContributed(sessionId: String) {
        synchronized(lock) {
            if (!active) return
            _state.value = DescriptorSessionState.Contributed(sessionId, 0.toUShort())
        }
    }

    fun clearSessionState() {
        synchronized(lock) {
            _state.value = DescriptorSessionState.Idle
        }
    }

    fun clearAll() {
        synchronized(lock) {
            active = false
            _state.value = DescriptorSessionState.Idle
            _pendingProposals.value = emptyList()
            _announcedXpubs.value = emptyMap()
            _callbacksRegistered.value = false
        }
    }

    fun activate() {
        synchronized(lock) {
            active = true
        }
    }

    private fun doRemovePendingProposal(sessionId: String) {
        _pendingProposals.update { it.filter { p -> p.sessionId != sessionId } }
    }

    fun removePendingProposal(sessionId: String) {
        synchronized(lock) {
            doRemovePendingProposal(sessionId)
        }
    }
}

@Composable
fun WalletDescriptorScreen(
    keepMobile: KeepMobile,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val loadFailedMessage = stringResource(R.string.wallet_descriptor_toast_load_failed)
    val proposeFailedMessage = stringResource(R.string.wallet_descriptor_toast_propose_failed)
    val copiedMessage = stringResource(R.string.wallet_descriptor_toast_copied)
    val exportFailedMessage = stringResource(R.string.wallet_descriptor_toast_export_failed)
    val deleteFailedMessage = stringResource(R.string.wallet_descriptor_toast_delete_failed)
    val announceFailedMessage = stringResource(R.string.wallet_descriptor_toast_announce_failed)
    val rejectFailedMessage = stringResource(R.string.wallet_descriptor_toast_reject_failed)
    val approveFailedMessage = stringResource(R.string.wallet_descriptor_toast_approve_failed)
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
    var showKeyProofDialog by remember { mutableStateOf<DescriptorProposal?>(null) }
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
                Toast.makeText(context, loadFailedMessage, Toast.LENGTH_SHORT).show()
            }
        }
    }

    LaunchedEffect(Unit) {
        refreshDescriptors()
    }

    LaunchedEffect(sessionState) {
        when (sessionState) {
            is DescriptorSessionState.Complete -> {
                refreshDescriptors()
            }
            is DescriptorSessionState.ContributionNeeded,
            is DescriptorSessionState.Contributed,
            is DescriptorSessionState.Proposed -> {
                var failures = 0
                var delayMs = POLL_INTERVAL_MS
                val deadline = System.currentTimeMillis() + POLL_DEADLINE_MS
                while (failures < MAX_POLL_RETRIES && System.currentTimeMillis() < deadline) {
                    delay(delayMs)
                    runCatching {
                        withContext(Dispatchers.IO) { keepMobile.walletDescriptorList() }
                    }.onSuccess { fresh ->
                        failures = 0
                        delayMs = POLL_INTERVAL_MS
                        if (fresh.toSet() != descriptors.toSet()) {
                            descriptors = fresh
                        }
                    }.onFailure { e ->
                        if (e is CancellationException) throw e
                        failures++
                        delayMs = (delayMs * 2).coerceAtMost(MAX_POLL_INTERVAL_MS)
                        if (BuildConfig.DEBUG) Log.w(TAG, "Polling descriptors failed: ${e.javaClass.simpleName}")
                    }
                }
            }
            else -> {}
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

    fun handleProposalAction(
        proposal: DescriptorProposal,
        action: String,
        failureMessage: String,
        onSuccess: (() -> Unit)? = null,
        block: suspend (String) -> Unit
    ) {
        if (proposal.sessionId in inFlightSessions) return
        inFlightSessions = inFlightSessions + proposal.sessionId
        scope.launch {
            try {
                runCatching {
                    withContext(Dispatchers.IO) { block(proposal.sessionId) }
                }.onSuccess {
                    DescriptorSessionManager.removePendingProposal(proposal.sessionId)
                    onSuccess?.invoke()
                }.onFailure { e ->
                    if (e is CancellationException) throw e
                    if (BuildConfig.DEBUG) Log.w(TAG, "Failed to $action contribution: ${e.javaClass.simpleName}")
                    Toast.makeText(context, failureMessage, Toast.LENGTH_LONG).show()
                }
            } finally {
                inFlightSessions = inFlightSessions - proposal.sessionId
            }
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
        Text(stringResource(R.string.wallet_descriptor_title), style = MaterialTheme.typography.headlineMedium)
        Spacer(modifier = Modifier.height(16.dp))

        if (!callbacksRegistered) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer
                )
            ) {
                Text(
                    stringResource(R.string.wallet_descriptor_realtime_unavailable),
                    modifier = Modifier.padding(16.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    style = MaterialTheme.typography.bodySmall
                )
            }
            Spacer(modifier = Modifier.height(16.dp))
        }

        SessionStatusCard(sessionState)

        if (pendingProposals.isNotEmpty()) {
            Spacer(modifier = Modifier.height(16.dp))

            PendingContributionsCard(
                proposals = pendingProposals,
                inFlightSessions = inFlightSessions,
                onApprove = { showKeyProofDialog = it },
                onReject = { handleProposalAction(it, "reject", rejectFailedMessage) { id ->
                    keepMobile.walletDescriptorCancel(id)
                }}
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = { showProposeDialog = true },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.wallet_descriptor_new))
        }

        Spacer(modifier = Modifier.height(8.dp))

        Button(
            onClick = { showAnnounceDialog = true },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.secondary
            )
        ) {
            Text(stringResource(R.string.wallet_descriptor_announce_recovery_keys))
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
            Text(stringResource(R.string.back))
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
                            if (BuildConfig.DEBUG) Log.w(TAG, "Failed to propose descriptor: ${e.javaClass.simpleName}")
                            Toast.makeText(context, proposeFailedMessage, Toast.LENGTH_LONG).show()
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
                            Toast.makeText(context, copiedMessage, Toast.LENGTH_SHORT).show()
                        }.onSuccess {
                            showExportDialog = null
                        }.onFailure { e ->
                            if (e is CancellationException) throw e
                            if (BuildConfig.DEBUG) Log.w(TAG, "Failed to export descriptor: ${e.javaClass.simpleName}")
                            Toast.makeText(context, exportFailedMessage, Toast.LENGTH_LONG).show()
                        }
                    } finally {
                        isExporting = false
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
                            if (BuildConfig.DEBUG) Log.w(TAG, "Failed to delete descriptor: ${e.javaClass.simpleName}")
                            Toast.makeText(context, deleteFailedMessage, Toast.LENGTH_LONG).show()
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
                            if (BuildConfig.DEBUG) Log.w(TAG, "Failed to announce xpubs: ${e.javaClass.simpleName}")
                            Toast.makeText(context, announceFailedMessage, Toast.LENGTH_LONG).show()
                        }
                    } finally {
                        isAnnouncing = false
                    }
                }
            },
            onDismiss = { showAnnounceDialog = false }
        )
    }

    showKeyProofDialog?.let { proposal ->
        KeyProofConfirmDialog(
            proposal = proposal,
            isBusy = proposal.sessionId in inFlightSessions,
            onConfirm = {
                handleProposalAction(
                    proposal,
                    "approve",
                    approveFailedMessage,
                    onSuccess = {
                        DescriptorSessionManager.setContributed(proposal.sessionId)
                        showKeyProofDialog = null
                    }
                ) { id ->
                    keepMobile.walletDescriptorApproveContribution(id)
                }
            },
            onDismiss = { showKeyProofDialog = null }
        )
    }
}

@Composable
private fun KeyProofConfirmDialog(
    proposal: DescriptorProposal,
    isBusy: Boolean,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.wallet_descriptor_key_proof_title)) },
        text = {
            Column {
                Text(stringResource(R.string.wallet_descriptor_key_proof_body))
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    stringResource(R.string.wallet_descriptor_key_proof_network, proposal.network),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    stringResource(R.string.wallet_descriptor_key_proof_tiers, proposal.tiers.size),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    stringResource(R.string.wallet_descriptor_key_proof_required),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.tertiary
                )
            }
        },
        confirmButton = {
            Button(onClick = onConfirm, enabled = !isBusy) {
                Text(
                    if (isBusy) stringResource(R.string.wallet_descriptor_key_proof_confirming)
                    else stringResource(R.string.wallet_descriptor_key_proof_confirm)
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !isBusy) {
                Text(stringResource(R.string.wallet_descriptor_cancel))
            }
        }
    )
}

@Composable
private fun SessionStatusCard(state: DescriptorSessionState) {
    val (statusText, statusColor) = when (state) {
        is DescriptorSessionState.Idle -> return
        is DescriptorSessionState.Proposed ->
            stringResource(R.string.wallet_descriptor_session_proposed) to MaterialTheme.colorScheme.primary
        is DescriptorSessionState.ContributionNeeded ->
            stringResource(R.string.wallet_descriptor_session_contribution_needed) to MaterialTheme.colorScheme.tertiary
        is DescriptorSessionState.Contributed ->
            (if (state.shareIndex > 0u)
                stringResource(R.string.wallet_descriptor_session_share_contributed, state.shareIndex.toInt())
            else
                stringResource(R.string.wallet_descriptor_session_contribution_sent)) to
                MaterialTheme.colorScheme.secondary
        is DescriptorSessionState.Complete ->
            stringResource(R.string.wallet_descriptor_session_complete) to MaterialTheme.colorScheme.primary
        is DescriptorSessionState.Failed ->
            (if (BuildConfig.DEBUG)
                stringResource(R.string.wallet_descriptor_session_failed_debug, truncateText(state.error, 80))
            else
                stringResource(R.string.wallet_descriptor_session_failed)) to
                MaterialTheme.colorScheme.error
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(stringResource(R.string.wallet_descriptor_session_status), style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            Text(statusText, color = statusColor, style = MaterialTheme.typography.bodyMedium)
            if (BuildConfig.DEBUG && state is DescriptorSessionState.Complete) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    stringResource(R.string.wallet_descriptor_session_external_debug, truncateText(state.externalDescriptor, 40)),
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
            Text(stringResource(R.string.wallet_descriptor_pending_title), style = MaterialTheme.typography.titleMedium)
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
                            pluralStringResource(R.plurals.wallet_descriptor_pending_tiers, proposal.tiers.size, proposal.tiers.size),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            stringResource(R.string.wallet_descriptor_pending_proof_note),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.tertiary
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        val busy = proposal.sessionId in inFlightSessions
                        OutlinedButton(onClick = { onReject(proposal) }, enabled = !busy) {
                            Text(stringResource(R.string.wallet_descriptor_pending_reject))
                        }
                        Button(onClick = { onApprove(proposal) }, enabled = !busy) {
                            Text(stringResource(R.string.wallet_descriptor_pending_approve))
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
            Text(
                stringResource(R.string.wallet_descriptor_list_title, descriptors.size),
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(modifier = Modifier.height(8.dp))
            if (descriptors.isEmpty()) {
                Text(
                    stringResource(R.string.wallet_descriptor_list_empty),
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
                formatTimestampDetailed(descriptor.createdAt.toLong()),
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
                Text(stringResource(R.string.wallet_descriptor_row_export))
            }
            OutlinedButton(
                onClick = { onDelete(descriptor) },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                )
            ) {
                Text(stringResource(R.string.wallet_descriptor_row_delete))
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
        title = { Text(stringResource(R.string.wallet_descriptor_propose_title)) },
        text = {
            Column {
                Text(stringResource(R.string.wallet_descriptor_propose_network_label), style = MaterialTheme.typography.labelMedium)
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
                Text(stringResource(R.string.wallet_descriptor_propose_tier_label), style = MaterialTheme.typography.labelMedium)
                Spacer(modifier = Modifier.height(8.dp))
                val thresholdError = threshold.isNotEmpty() && threshold.toUIntOrNull()?.let { it !in 1u..15u } == true
                val thresholdLabel = stringResource(R.string.wallet_descriptor_propose_threshold_label)
                val requiredText = stringResource(R.string.wallet_descriptor_propose_required)
                val thresholdRangeText = stringResource(R.string.wallet_descriptor_propose_threshold_range)
                OutlinedTextField(
                    value = threshold,
                    onValueChange = { threshold = it.filter { c -> c.isDigit() } },
                    label = { Text(thresholdLabel) },
                    isError = thresholdError || (threshold.isEmpty()),
                    supportingText = if (threshold.isEmpty()) {
                        { Text(requiredText) }
                    } else if (thresholdError) {
                        { Text(thresholdRangeText) }
                    } else null,
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                val timelockError = timelockMonths.isNotEmpty() && timelockMonths.toUIntOrNull()?.let { it !in 1u..120u } == true
                val timelockLabel = stringResource(R.string.wallet_descriptor_propose_timelock_label)
                val timelockRangeText = stringResource(R.string.wallet_descriptor_propose_timelock_range)
                OutlinedTextField(
                    value = timelockMonths,
                    onValueChange = { timelockMonths = it.filter { c -> c.isDigit() } },
                    label = { Text(timelockLabel) },
                    isError = timelockError || (timelockMonths.isEmpty()),
                    supportingText = if (timelockMonths.isEmpty()) {
                        { Text(requiredText) }
                    } else if (timelockError) {
                        { Text(timelockRangeText) }
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
                Text(
                    if (isProposing) stringResource(R.string.wallet_descriptor_propose_confirming)
                    else stringResource(R.string.wallet_descriptor_propose_confirm)
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.wallet_descriptor_cancel)) }
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
        title = { Text(stringResource(R.string.wallet_descriptor_export_title)) },
        text = {
            Column {
                Text(
                    truncateGroupPubkey(descriptor.groupPubkey),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    if (isExporting) stringResource(R.string.wallet_descriptor_export_exporting)
                    else stringResource(R.string.wallet_descriptor_export_choose)
                )
            }
        },
        confirmButton = {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { onExport(ExportFormat.SPARROW) }, enabled = !isExporting) {
                    Text(stringResource(R.string.wallet_descriptor_export_sparrow))
                }
                TextButton(onClick = { onExport(ExportFormat.RAW) }, enabled = !isExporting) {
                    Text(stringResource(R.string.wallet_descriptor_export_raw))
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.wallet_descriptor_cancel)) }
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
        title = { Text(stringResource(R.string.wallet_descriptor_delete_title)) },
        text = {
            Text(
                stringResource(
                    R.string.wallet_descriptor_delete_body,
                    truncateGroupPubkey(descriptor.groupPubkey)
                )
            )
        },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                enabled = !isDeleting,
                colors = ButtonDefaults.textButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                )
            ) {
                Text(
                    if (isDeleting) stringResource(R.string.wallet_descriptor_delete_deleting)
                    else stringResource(R.string.wallet_descriptor_delete_confirm)
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.wallet_descriptor_cancel)) }
        }
    )
}

@Composable
private fun AnnouncedXpubsCard(announcedXpubs: Map<UShort, List<AnnouncedXpubInfo>>) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(stringResource(R.string.wallet_descriptor_announced_title), style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            val sorted = announcedXpubs.entries.sortedBy { it.key }
            sorted.forEachIndexed { index, (shareIndex, xpubs) ->
                Text(
                    stringResource(R.string.wallet_descriptor_announced_share, shareIndex.toInt()),
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
                                stringResource(R.string.wallet_descriptor_announced_fingerprint, xpub.fingerprint),
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
                if (index < sorted.lastIndex) {
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
    val fpValid = fingerprint.matches(FP_REGEX)
    val fpError = fingerprint.isNotEmpty() && !fpValid

    val xpubLabel = stringResource(R.string.wallet_descriptor_announce_xpub_label)
    val requiredText = stringResource(R.string.wallet_descriptor_propose_required)
    val xpubPrefixError = stringResource(R.string.wallet_descriptor_announce_xpub_prefix_error)
    val fpLabel = stringResource(R.string.wallet_descriptor_announce_fp_label)
    val fpErrorText = stringResource(R.string.wallet_descriptor_announce_fp_error)
    val labelLabel = stringResource(R.string.wallet_descriptor_announce_label_label)
    val labelPlaceholder = stringResource(R.string.wallet_descriptor_announce_label_placeholder)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.wallet_descriptor_announce_title)) },
        text = {
            Column {
                OutlinedTextField(
                    value = xpub,
                    onValueChange = { xpub = it.take(200) },
                    label = { Text(xpubLabel) },
                    isError = trimmedXpub.isEmpty() || xpubFormatError,
                    supportingText = when {
                        trimmedXpub.isEmpty() -> {{ Text(requiredText) }}
                        xpubFormatError -> {{ Text(xpubPrefixError) }}
                        else -> null
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = fingerprint,
                    onValueChange = { fingerprint = it.filter { c -> c.isDigit() || c in 'a'..'f' || c in 'A'..'F' }.take(8) },
                    label = { Text(fpLabel) },
                    isError = fingerprint.isEmpty() || fpError,
                    supportingText = when {
                        fingerprint.isEmpty() -> {{ Text(requiredText) }}
                        fpError -> {{ Text(fpErrorText) }}
                        else -> null
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it.filter { c -> !c.isISOControl() }.take(64) },
                    label = { Text(labelLabel) },
                    placeholder = { Text(labelPlaceholder) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            val valid = trimmedXpub.isNotEmpty() && !xpubFormatError && fpValid
            TextButton(
                onClick = { onAnnounce(xpub.trim(), fingerprint, label) },
                enabled = valid && !isAnnouncing
            ) {
                Text(
                    if (isAnnouncing) stringResource(R.string.wallet_descriptor_announce_confirming)
                    else stringResource(R.string.wallet_descriptor_announce_confirm)
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.wallet_descriptor_cancel)) }
        }
    )
}
