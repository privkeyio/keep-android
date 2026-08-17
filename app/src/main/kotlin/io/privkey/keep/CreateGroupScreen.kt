package io.privkey.keep

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.Log
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.privkey.keep.uniffi.DkgConfig
import io.privkey.keep.uniffi.DkgParticipant
import io.privkey.keep.uniffi.DkgProgressUpdate
import org.json.JSONArray
import org.json.JSONObject
import javax.crypto.Cipher

private const val MAX_PARTICIPANTS = 8
private const val MIN_THRESHOLD = 2
private const val MAX_QR_LENGTH = 8192
private const val INVITE_VERSION = 2

// Per-group signing subkey pubkeys are nostr x-only pubkeys rendered as 64-char
// lowercase hex by frost_dkg_begin.
private fun isHex64(s: String): Boolean =
    s.length == 64 && s.all { it in '0'..'9' || it in 'a'..'f' }

private data class SetupPayload(
    val name: String,
    val threshold: Int,
    val participants: Int,
    val relays: List<String>
)

private data class RosterEntry(val index: Int, val pubkey: String)

private data class RosterPayload(
    val name: String,
    val threshold: Int,
    val participants: Int,
    val relays: List<String>,
    val roster: List<RosterEntry>
)

private fun relaysFromJson(obj: JSONObject): List<String> {
    val arr = obj.optJSONArray("relays") ?: JSONArray()
    return (0 until arr.length()).mapNotNull { arr.optString(it, null) }
}

private fun kind(data: String): String? = try {
    val obj = JSONObject(data.trim())
    if (obj.optInt("v", -1) == INVITE_VERSION) obj.optString("k", "") else null
} catch (_: Exception) {
    null
} catch (_: StackOverflowError) {
    null
}

// --- Setup code (coordinator -> joiners) ---

internal fun isValidSetup(data: String): Boolean {
    if (data.length > MAX_QR_LENGTH) return false
    if (kind(data) != "setup") return false
    return try {
        val obj = JSONObject(data.trim())
        val participants = obj.optInt("n", -1)
        val threshold = obj.optInt("th", -1)
        obj.optString("name", "").isNotEmpty() &&
            participants in MIN_THRESHOLD..MAX_PARTICIPANTS &&
            threshold in MIN_THRESHOLD..participants
    } catch (_: Exception) {
        false
    }
}

private fun parseSetup(data: String): SetupPayload? {
    if (!isValidSetup(data)) return null
    return try {
        val obj = JSONObject(data.trim())
        SetupPayload(
            name = obj.getString("name"),
            threshold = obj.getInt("th"),
            participants = obj.getInt("n"),
            relays = relaysFromJson(obj)
        )
    } catch (_: Exception) {
        null
    }
}

private fun buildSetupJson(setup: SetupPayload): String = JSONObject().apply {
    put("v", INVITE_VERSION)
    put("k", "setup")
    put("name", setup.name)
    put("th", setup.threshold)
    put("n", setup.participants)
    put("relays", JSONArray(setup.relays))
}.toString()

// --- Subkey code (joiner -> coordinator) ---

internal fun isValidSubkey(data: String): Boolean {
    if (data.length > MAX_QR_LENGTH) return false
    if (kind(data) != "subkey") return false
    return try {
        val obj = JSONObject(data.trim())
        obj.optString("name", "").isNotEmpty() && isHex64(obj.optString("pk", ""))
    } catch (_: Exception) {
        false
    }
}

private fun parseSubkey(data: String): Pair<String, String>? {
    if (!isValidSubkey(data)) return null
    return try {
        val obj = JSONObject(data.trim())
        obj.getString("name") to obj.getString("pk")
    } catch (_: Exception) {
        null
    }
}

private fun buildSubkeyJson(name: String, pubkey: String): String = JSONObject().apply {
    put("v", INVITE_VERSION)
    put("k", "subkey")
    put("name", name)
    put("pk", pubkey)
}.toString()

// --- Roster code (coordinator -> all) ---

internal fun isValidRoster(data: String): Boolean {
    if (data.length > MAX_QR_LENGTH) return false
    if (kind(data) != "roster") return false
    return try {
        val obj = JSONObject(data.trim())
        val participants = obj.optInt("n", -1)
        val threshold = obj.optInt("th", -1)
        val entries = obj.optJSONArray("r") ?: return false
        if (obj.optString("name", "").isEmpty()) return false
        if (participants !in MIN_THRESHOLD..MAX_PARTICIPANTS) return false
        if (threshold !in MIN_THRESHOLD..participants) return false
        if (entries.length() != participants) return false
        val seenIdx = HashSet<Int>()
        val seenPk = HashSet<String>()
        for (i in 0 until entries.length()) {
            val e = entries.optJSONObject(i) ?: return false
            val idx = e.optInt("i", -1)
            val pk = e.optString("pk", "")
            if (idx !in 1..participants || !isHex64(pk)) return false
            if (!seenIdx.add(idx) || !seenPk.add(pk)) return false
        }
        // Unique indices in 1..participants filling all `participants` slots means
        // the set is exactly {1..participants}, so index 1 (coordinator) is present.
        true
    } catch (_: Exception) {
        false
    }
}

private fun parseRoster(data: String): RosterPayload? {
    if (!isValidRoster(data)) return null
    return try {
        val obj = JSONObject(data.trim())
        val entries = obj.getJSONArray("r")
        val roster = (0 until entries.length()).map {
            val e = entries.getJSONObject(it)
            RosterEntry(e.getInt("i"), e.getString("pk"))
        }
        RosterPayload(
            name = obj.getString("name"),
            threshold = obj.getInt("th"),
            participants = obj.getInt("n"),
            relays = relaysFromJson(obj),
            roster = roster
        )
    } catch (_: Exception) {
        null
    }
}

private fun buildRosterJson(roster: RosterPayload): String = JSONObject().apply {
    put("v", INVITE_VERSION)
    put("k", "roster")
    put("name", roster.name)
    put("th", roster.threshold)
    put("n", roster.participants)
    put("relays", JSONArray(roster.relays))
    put("r", JSONArray().apply {
        roster.roster.forEach { entry ->
            put(JSONObject().apply {
                put("i", entry.index)
                put("pk", entry.pubkey)
            })
        }
    })
}.toString()

private fun dkgConfig(roster: RosterPayload, ourIndex: Int): DkgConfig = DkgConfig(
    groupName = roster.name,
    threshold = roster.threshold.toUShort(),
    participants = roster.participants.toUShort(),
    ourIndex = ourIndex.toUShort(),
    relays = roster.relays,
    roster = roster.roster.map { DkgParticipant(it.index.toUShort(), it.pubkey) }
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateGroupScreen(
    relays: List<String>,
    onCreateGroup: (config: DkgConfig, name: String, cipher: Cipher) -> Unit,
    onDkgBegin: (name: String) -> String,
    onCancel: () -> Unit,
    onGetCipher: () -> Cipher,
    onBiometricAuth: (Cipher, (Cipher?) -> Unit) -> Unit,
    onDismiss: () -> Unit,
    createGroupState: CreateGroupState
) {
    val context = LocalContext.current
    var isJoinMode by remember { mutableStateOf(false) }

    val biometricInvalidatedMessage = stringResource(R.string.import_share_biometric_invalidated)
    val biometricUnavailableMessage = stringResource(R.string.import_share_biometric_unavailable)
    val initFailedMessage = stringResource(R.string.import_share_init_failed)

    DisposableEffect(context) {
        setSecureScreen(context, true)
        onDispose { setSecureScreen(context, false) }
    }

    val runDkg: (DkgConfig, String, (String) -> Unit) -> Unit = { config, name, onError ->
        try {
            val cipher = onGetCipher()
            onBiometricAuth(cipher) { authedCipher ->
                if (authedCipher != null) {
                    onCreateGroup(config, name, authedCipher)
                }
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            if (BuildConfig.DEBUG) Log.e("CreateGroup", "Biometric key invalidated: ${e::class.simpleName}")
            onError(biometricInvalidatedMessage)
        } catch (e: BiometricHelper.BiometricNotReadyException) {
            onError(e.message ?: biometricUnavailableMessage)
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.e("CreateGroup", "Cipher init failed: ${e::class.simpleName}")
            onError(initFailedMessage)
        }
    }

    if (createGroupState !is CreateGroupState.Idle) {
        DkgRunView(state = createGroupState, onCancel = onCancel, onDismiss = onDismiss)
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = stringResource(R.string.create_group_title),
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(16.dp))

        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            SegmentedButton(
                selected = !isJoinMode,
                onClick = { isJoinMode = false },
                shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
            ) {
                Text(stringResource(R.string.create_group_mode_start))
            }
            SegmentedButton(
                selected = isJoinMode,
                onClick = { isJoinMode = true },
                shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
            ) {
                Text(stringResource(R.string.create_group_mode_join))
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        if (isJoinMode) {
            JoinGroupMode(onDkgBegin = onDkgBegin, runDkg = runDkg)
        } else {
            StartGroupMode(relays = relays, onDkgBegin = onDkgBegin, runDkg = runDkg)
        }

        Spacer(modifier = Modifier.height(24.dp))

        OutlinedButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.create_group_cancel))
        }
    }
}

private enum class CoordPhase { Form, Collect, Ready }

@Composable
private fun StartGroupMode(
    relays: List<String>,
    onDkgBegin: (String) -> String,
    runDkg: (DkgConfig, String, (String) -> Unit) -> Unit
) {
    val defaultName = stringResource(R.string.create_group_default_name)
    var name by remember { mutableStateOf(defaultName) }
    var threshold by remember { mutableStateOf(2) }
    var participants by remember { mutableStateOf(3) }
    var phase by remember { mutableStateOf(CoordPhase.Form) }
    var myPubkey by remember { mutableStateOf<String?>(null) }
    val collected = remember { mutableStateListOf<String>() }
    var showScanner by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    val beginFailedMessage = stringResource(R.string.create_group_begin_failed)
    val wrongGroupMessage = stringResource(R.string.create_group_wrong_group)
    val duplicateMessage = stringResource(R.string.create_group_duplicate_participant)
    val scanParticipantTitle = stringResource(R.string.create_group_scan_participant_title)

    if (showScanner) {
        QrScannerScreen(
            onCodeScanned = { code ->
                showScanner = false
                val parsed = parseSubkey(code)
                when {
                    parsed == null -> {}
                    parsed.first != name -> errorMessage = wrongGroupMessage
                    parsed.second == myPubkey || collected.contains(parsed.second) ->
                        errorMessage = duplicateMessage
                    else -> {
                        errorMessage = null
                        collected.add(parsed.second)
                    }
                }
            },
            onDismiss = { showScanner = false },
            validator = ::isValidSubkey,
            title = scanParticipantTitle
        )
        return
    }

    when (phase) {
        CoordPhase.Form -> {
            OutlinedTextField(
                value = name,
                onValueChange = { if (it.length <= MAX_ACCOUNT_NAME_LENGTH) name = it },
                label = { Text(stringResource(R.string.create_group_name_label)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(16.dp))

            Stepper(
                label = stringResource(R.string.create_group_threshold_label, threshold),
                onDecrement = { if (threshold > MIN_THRESHOLD) threshold-- },
                onIncrement = { if (threshold < participants) threshold++ },
                canDecrement = threshold > MIN_THRESHOLD,
                canIncrement = threshold < participants
            )

            Spacer(modifier = Modifier.height(8.dp))

            Stepper(
                label = stringResource(R.string.create_group_participants_label, participants),
                onDecrement = {
                    if (participants > MIN_THRESHOLD) {
                        participants--
                        if (threshold > participants) threshold = participants
                    }
                },
                onIncrement = { if (participants < MAX_PARTICIPANTS) participants++ },
                canDecrement = participants > MIN_THRESHOLD,
                canIncrement = participants < MAX_PARTICIPANTS
            )

            Spacer(modifier = Modifier.height(24.dp))

            ErrorText(errorMessage)

            Button(
                onClick = {
                    try {
                        myPubkey = onDkgBegin(name)
                        collected.clear()
                        errorMessage = null
                        phase = CoordPhase.Collect
                    } catch (e: Exception) {
                        if (BuildConfig.DEBUG) Log.e("CreateGroup", "dkgBegin failed: ${e::class.simpleName}")
                        errorMessage = beginFailedMessage
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = relays.isNotEmpty()
            ) {
                Text(stringResource(R.string.create_group_begin))
            }

            if (relays.isEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.create_group_no_relays),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        CoordPhase.Collect -> {
            val setupJson = buildSetupJson(SetupPayload(name, threshold, participants, relays))

            QrCodeDisplay(
                data = setupJson,
                label = stringResource(R.string.create_group_setup_qr_label)
            )

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = stringResource(R.string.create_group_collect_instructions),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = stringResource(
                    R.string.create_group_collect_progress,
                    collected.size,
                    participants - 1
                ),
                style = MaterialTheme.typography.bodyLarge
            )

            Spacer(modifier = Modifier.height(16.dp))

            ErrorText(errorMessage)

            if (collected.size >= participants - 1) {
                Button(
                    onClick = { phase = CoordPhase.Ready },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(stringResource(R.string.create_group_roster_qr_label))
                }
            } else {
                Button(
                    onClick = { showScanner = true },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(stringResource(R.string.create_group_scan_participant))
                }
            }
        }

        CoordPhase.Ready -> {
            val entries = buildList {
                add(RosterEntry(1, myPubkey!!))
                collected.forEachIndexed { i, pk -> add(RosterEntry(i + 2, pk)) }
            }
            val roster = RosterPayload(name, threshold, participants, relays, entries)
            val rosterJson = buildRosterJson(roster)

            QrCodeDisplay(
                data = rosterJson,
                label = stringResource(R.string.create_group_roster_qr_label)
            )

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = stringResource(R.string.create_group_roster_ready),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(24.dp))

            ErrorText(errorMessage)

            Button(
                onClick = {
                    errorMessage = null
                    runDkg(dkgConfig(roster, 1), name) { errorMessage = it }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.create_group_start_dkg))
            }
        }
    }
}

private enum class JoinPhase { ScanSetup, ShowSubkey, Ready }

@Composable
private fun JoinGroupMode(
    onDkgBegin: (String) -> String,
    runDkg: (DkgConfig, String, (String) -> Unit) -> Unit
) {
    var phase by remember { mutableStateOf(JoinPhase.ScanSetup) }
    var setup by remember { mutableStateOf<SetupPayload?>(null) }
    var myPubkey by remember { mutableStateOf<String?>(null) }
    var roster by remember { mutableStateOf<RosterPayload?>(null) }
    var ourIndex by remember { mutableStateOf(0) }
    var scanSetup by remember { mutableStateOf(false) }
    var scanRoster by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    val beginFailedMessage = stringResource(R.string.create_group_begin_failed)
    val wrongGroupMessage = stringResource(R.string.create_group_wrong_group)
    val notInRosterMessage = stringResource(R.string.create_group_not_in_roster)
    val scanSetupTitle = stringResource(R.string.create_group_scan_setup_title)
    val scanRosterTitle = stringResource(R.string.create_group_scan_roster_title)

    if (scanSetup) {
        QrScannerScreen(
            onCodeScanned = { code ->
                scanSetup = false
                val parsed = parseSetup(code)
                if (parsed != null) {
                    try {
                        myPubkey = onDkgBegin(parsed.name)
                        setup = parsed
                        errorMessage = null
                        phase = JoinPhase.ShowSubkey
                    } catch (e: Exception) {
                        if (BuildConfig.DEBUG) Log.e("CreateGroup", "dkgBegin failed: ${e::class.simpleName}")
                        errorMessage = beginFailedMessage
                    }
                }
            },
            onDismiss = { scanSetup = false },
            validator = ::isValidSetup,
            title = scanSetupTitle
        )
        return
    }

    if (scanRoster) {
        val currentSetup = setup
        val mine = myPubkey
        QrScannerScreen(
            onCodeScanned = { code ->
                scanRoster = false
                val parsed = parseRoster(code)
                val idx = parsed?.roster?.firstOrNull { it.pubkey == mine }?.index
                when {
                    parsed == null || currentSetup == null || mine == null -> {}
                    parsed.name != currentSetup.name ||
                        parsed.threshold != currentSetup.threshold ||
                        parsed.participants != currentSetup.participants ->
                        errorMessage = wrongGroupMessage
                    idx == null -> errorMessage = notInRosterMessage
                    else -> {
                        errorMessage = null
                        roster = parsed
                        ourIndex = idx
                        phase = JoinPhase.Ready
                    }
                }
            },
            onDismiss = { scanRoster = false },
            validator = ::isValidRoster,
            title = scanRosterTitle
        )
        return
    }

    when (phase) {
        JoinPhase.ScanSetup -> {
            Text(
                text = stringResource(R.string.create_group_join_scan_setup),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(16.dp))
            ErrorText(errorMessage)
            Button(onClick = { scanSetup = true }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.create_group_scan_setup))
            }
        }

        JoinPhase.ShowSubkey -> {
            val currentSetup = setup!!
            QrCodeDisplay(
                data = buildSubkeyJson(currentSetup.name, myPubkey!!),
                label = stringResource(R.string.create_group_subkey_qr_label)
            )

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = stringResource(R.string.create_group_show_subkey),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(24.dp))

            ErrorText(errorMessage)

            Button(onClick = { scanRoster = true }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.create_group_scan_roster))
            }
        }

        JoinPhase.Ready -> {
            val currentRoster = roster!!
            Text(
                text = stringResource(
                    R.string.create_group_joiner_ready,
                    currentRoster.threshold,
                    currentRoster.participants,
                    ourIndex
                ),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(24.dp))

            ErrorText(errorMessage)

            Button(
                onClick = {
                    errorMessage = null
                    runDkg(dkgConfig(currentRoster, ourIndex), currentRoster.name) { errorMessage = it }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.create_group_join_dkg))
            }
        }
    }
}

@Composable
private fun ErrorText(message: String?) {
    message?.let {
        StatusCard(
            text = it,
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer
        )
        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
private fun Stepper(
    label: String,
    onDecrement: () -> Unit,
    onIncrement: () -> Unit,
    canDecrement: Boolean,
    canIncrement: Boolean
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label, style = MaterialTheme.typography.bodyLarge)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onDecrement, enabled = canDecrement) {
                Text(stringResource(R.string.create_group_stepper_minus))
            }
            OutlinedButton(onClick = onIncrement, enabled = canIncrement) {
                Text(stringResource(R.string.create_group_stepper_plus))
            }
        }
    }
}

@Composable
private fun DkgRunView(
    state: CreateGroupState,
    onCancel: () -> Unit,
    onDismiss: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = stringResource(R.string.create_group_title),
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(32.dp))

        when (state) {
            is CreateGroupState.Running -> {
                CircularProgressIndicator()
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = dkgStatusText(state.update),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(24.dp))
                OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.create_group_cancel))
                }
            }
            is CreateGroupState.Success -> {
                StatusCard(
                    text = stringResource(
                        R.string.create_group_success,
                        state.name,
                        io.privkey.keep.uniffi.truncateStr(state.groupPubkey, 8u, 6u)
                    ),
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
                Spacer(modifier = Modifier.height(24.dp))
                Button(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.create_group_done))
                }
            }
            is CreateGroupState.Error -> {
                StatusCard(
                    text = state.message,
                    containerColor = MaterialTheme.colorScheme.errorContainer,
                    contentColor = MaterialTheme.colorScheme.onErrorContainer
                )
                Spacer(modifier = Modifier.height(24.dp))
                OutlinedButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.create_group_back))
                }
            }
            CreateGroupState.Idle -> {}
        }
    }
}

@Composable
private fun dkgStatusText(update: DkgProgressUpdate): String = when (update) {
    is DkgProgressUpdate.Connecting -> stringResource(R.string.create_group_status_connecting)
    is DkgProgressUpdate.Round1 ->
        stringResource(R.string.create_group_status_round1, update.received.toInt(), update.total.toInt())
    is DkgProgressUpdate.Round2 ->
        stringResource(R.string.create_group_status_round2, update.received.toInt(), update.total.toInt())
    is DkgProgressUpdate.Confirming ->
        stringResource(R.string.create_group_status_confirming, update.confirmed.toInt(), update.total.toInt())
    is DkgProgressUpdate.Finalizing -> stringResource(R.string.create_group_status_finalizing)
    is DkgProgressUpdate.Complete -> stringResource(R.string.create_group_status_finalizing)
    is DkgProgressUpdate.Failed -> update.reason
}
