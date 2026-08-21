package io.privkey.keep

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.Log
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.privkey.keep.uniffi.DkgConfig
import io.privkey.keep.uniffi.DkgParticipant
import io.privkey.keep.uniffi.DkgProgressUpdate
import io.privkey.keep.uniffi.RosterVerification
import io.privkey.keep.uniffi.frostAssembleRoster
import io.privkey.keep.uniffi.frostVerifyRoster
import io.privkey.keep.uniffi.truncateStr
import org.json.JSONArray
import org.json.JSONObject
import javax.crypto.Cipher

private const val MAX_PARTICIPANTS = 8
private const val MIN_THRESHOLD = 2
private const val MAX_QR_LENGTH = 8192
private const val INVITE_VERSION = 2
// Mirror keep-core/src/relay.rs: MAX_RELAYS and MAX_RELAY_URL_LENGTH. Matching
// them lets a bad relay fail at the scan instead of deep inside frost_run_dkg.
private const val MAX_RELAYS = 10
private const val MAX_RELAY_LENGTH = 256

// Per-group signing subkey pubkeys are nostr x-only pubkeys rendered as 64-char
// lowercase hex by frost_dkg_begin.
private fun isHex64(s: String): Boolean =
    s.length == 64 && s.all { it in '0'..'9' || it in 'a'..'f' }

// Group names arrive from scanned QR payloads and become this device's account
// label (via frost_dkg_begin). Rust's validate_share_name only caps length at
// MAX_ACCOUNT_NAME_LENGTH, so reject control characters and Unicode bidi
// overrides/isolates here too: a scanned name must not carry an RTL override
// that spoofs how the label renders or inject control characters into it.
private fun isValidGroupName(name: String): Boolean =
    name.isNotEmpty() && name.length <= MAX_ACCOUNT_NAME_LENGTH &&
        name.none { it.isISOControl() || it in '\u202A'..'\u202E' || it in '\u2066'..'\u2069' }

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

// Relay URLs come from scanned payloads and are handed to frost_run_dkg as
// websocket endpoints, so bound the list and require the encrypted wss:// scheme
// rather than connecting to arbitrary attacker-supplied strings. Plaintext ws://
// is rejected in production Rust, so reject it here instead of minting a subkey
// and walking the whole flow only to die inside frost_run_dkg.
private fun relaysValid(relays: List<String>): Boolean =
    relays.isNotEmpty() && relays.size <= MAX_RELAYS &&
        relays.all { it.length <= MAX_RELAY_LENGTH && it.startsWith("wss://") }

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
        isValidGroupName(obj.optString("name", "")) &&
            participants in MIN_THRESHOLD..MAX_PARTICIPANTS &&
            threshold in MIN_THRESHOLD..participants &&
            relaysValid(relaysFromJson(obj))
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
        if (!isValidGroupName(obj.optString("name", ""))) return false
        if (participants !in MIN_THRESHOLD..MAX_PARTICIPANTS) return false
        if (threshold !in MIN_THRESHOLD..participants) return false
        if (!relaysValid(relaysFromJson(obj))) return false
        if (entries.length() != participants) return false
        // Shape pre-check only: enough to reject an obviously bad frame at the
        // scan. Index uniqueness, duplicate-pubkey rejection and group-id binding
        // are the authoritative job of frostVerifyRoster (Rust), run once the
        // frame is accepted, so they are not re-implemented here.
        for (i in 0 until entries.length()) {
            val e = entries.optJSONObject(i) ?: return false
            if (e.optInt("i", -1) !in 1..participants || !isHex64(e.optString("pk", ""))) {
                return false
            }
        }
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

// Validate the finalized roster and derive its fingerprint in Rust, the single
// authority for the DKG identity path (index range/uniqueness, duplicate-pubkey
// rejection, threshold bounds, and the canonical frost_group_id). `ourPubkey` is
// this device's per-group subkey; the returned index is resolved by matching it,
// and the fingerprint is a prefix of the same group id the run lands on, so the
// value read aloud out of band cannot drift from what the ceremony uses. Throws a
// typed KeepMobileException if the roster is malformed or this device is not in
// it; callers treat that as an invalid roster.
private fun verifyRoster(roster: RosterPayload, ourPubkey: String): RosterVerification =
    frostVerifyRoster(
        roster.name,
        roster.threshold.toUShort(),
        roster.participants.toUShort(),
        roster.roster.map { DkgParticipant(it.index.toUShort(), it.pubkey) },
        ourPubkey
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
    val rosterInvalidMessage = stringResource(R.string.create_group_roster_invalid)
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
                decrementDescription = stringResource(R.string.create_group_threshold_decrement),
                incrementDescription = stringResource(R.string.create_group_threshold_increment),
                onDecrement = { if (threshold > MIN_THRESHOLD) threshold-- },
                onIncrement = { if (threshold < participants) threshold++ },
                canDecrement = threshold > MIN_THRESHOLD,
                canIncrement = threshold < participants
            )

            Spacer(modifier = Modifier.height(8.dp))

            Stepper(
                label = stringResource(R.string.create_group_participants_label, participants),
                decrementDescription = stringResource(R.string.create_group_participants_decrement),
                incrementDescription = stringResource(R.string.create_group_participants_increment),
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
                    Text(stringResource(R.string.create_group_show_roster))
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
            val mine = myPubkey!!
            // Assemble (coordinator idx 1, joiners idx i+2) and validate + fingerprint
            // in Rust — the single authority for the roster identity path.
            val assembled = remember(mine, collected.toList()) {
                runCatching { frostAssembleRoster(mine, collected.toList()) }
                    .onFailure {
                        if (BuildConfig.DEBUG) {
                            Log.e("CreateGroup", "assembleRoster failed: ${it::class.simpleName}")
                        }
                    }
                    .getOrNull()
            }
            val roster = assembled?.let {
                RosterPayload(
                    name, threshold, participants, relays,
                    it.map { p -> RosterEntry(p.index.toInt(), p.pubkey) }
                )
            }
            val verification = remember(roster) {
                roster?.let { r ->
                    runCatching { verifyRoster(r, mine) }
                        .onFailure {
                            if (BuildConfig.DEBUG) {
                                Log.e("CreateGroup", "verifyRoster failed: ${it::class.simpleName}")
                            }
                        }
                        .getOrNull()
                }
            }
            var confirmed by remember { mutableStateOf(false) }

            if (roster == null || verification == null) {
                ErrorText(rosterInvalidMessage)
            } else {
                QrCodeDisplay(
                    data = buildRosterJson(roster),
                    label = stringResource(R.string.create_group_roster_qr_label)
                )

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = stringResource(R.string.create_group_roster_ready),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Spacer(modifier = Modifier.height(24.dp))

                RosterReview(
                    roster,
                    ourIndex = verification.ourIndex.toInt(),
                    fingerprint = verification.fingerprint,
                    confirmed = confirmed
                ) { confirmed = it }

                Spacer(modifier = Modifier.height(24.dp))

                ErrorText(errorMessage)

                Button(
                    onClick = {
                        errorMessage = null
                        runDkg(dkgConfig(roster, verification.ourIndex.toInt()), name) {
                            errorMessage = it
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = confirmed
                ) {
                    Text(stringResource(R.string.create_group_start_dkg))
                }
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
    var verification by remember { mutableStateOf<RosterVerification?>(null) }
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
                // Rust resolves this device's index by matching its subkey and
                // validates the roster (uniqueness, dup-pubkey, group id) in one
                // call; a null result means malformed or not in the roster.
                val verified = if (parsed != null && mine != null) {
                    runCatching { verifyRoster(parsed, mine) }
                        .onFailure {
                            if (BuildConfig.DEBUG) {
                                Log.e("CreateGroup", "verifyRoster failed: ${it::class.simpleName}")
                            }
                        }
                        .getOrNull()
                } else {
                    null
                }
                when {
                    parsed == null || currentSetup == null || mine == null -> {}
                    parsed.name != currentSetup.name ||
                        parsed.threshold != currentSetup.threshold ||
                        parsed.participants != currentSetup.participants ||
                        parsed.relays != currentSetup.relays ->
                        errorMessage = wrongGroupMessage
                    verified == null -> errorMessage = notInRosterMessage
                    else -> {
                        errorMessage = null
                        roster = parsed
                        verification = verified
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
            val ourIndex = verification!!.ourIndex.toInt()
            var confirmed by remember { mutableStateOf(false) }
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

            RosterReview(
                currentRoster,
                ourIndex = ourIndex,
                fingerprint = verification!!.fingerprint,
                confirmed = confirmed
            ) { confirmed = it }

            Spacer(modifier = Modifier.height(24.dp))

            ErrorText(errorMessage)

            Button(
                onClick = {
                    errorMessage = null
                    runDkg(dkgConfig(currentRoster, ourIndex), currentRoster.name) { errorMessage = it }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = confirmed
            ) {
                Text(stringResource(R.string.create_group_join_dkg))
            }
        }
    }
}

@Composable
private fun RosterReview(
    roster: RosterPayload,
    ourIndex: Int,
    fingerprint: String,
    confirmed: Boolean,
    onConfirmedChange: (Boolean) -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = stringResource(R.string.create_group_verify_title),
            style = MaterialTheme.typography.titleMedium
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.create_group_verify_instructions),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.create_group_fingerprint_label),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = fingerprint,
            style = MaterialTheme.typography.titleLarge,
            fontFamily = FontFamily.Monospace
        )
        Spacer(modifier = Modifier.height(16.dp))
        roster.roster.sortedBy { it.index }.forEach { entry ->
            val label = truncateStr(entry.pubkey, 8u, 6u)
            Text(
                text = if (entry.index == ourIndex)
                    stringResource(R.string.create_group_roster_member_you, entry.index, label)
                else
                    stringResource(R.string.create_group_roster_member, entry.index, label),
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 2.dp)
            )
        }
        Spacer(modifier = Modifier.height(16.dp))
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onConfirmedChange(!confirmed) }
        ) {
            Checkbox(checked = confirmed, onCheckedChange = onConfirmedChange)
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = stringResource(R.string.create_group_verify_confirm),
                style = MaterialTheme.typography.bodyMedium
            )
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
    decrementDescription: String,
    incrementDescription: String,
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
            OutlinedButton(
                onClick = onDecrement,
                enabled = canDecrement,
                modifier = Modifier.semantics { contentDescription = decrementDescription }
            ) {
                Text(stringResource(R.string.create_group_stepper_minus))
            }
            OutlinedButton(
                onClick = onIncrement,
                enabled = canIncrement,
                modifier = Modifier.semantics { contentDescription = incrementDescription }
            ) {
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
                // Cancel only signals Rust; a peer that finishes its round late can
                // keep frost_run_dkg blocked past the request, so the spinner would
                // otherwise trap the user. Once cancel is requested, surface a Leave
                // affordance: the run continues on the account scope and a persisted
                // share still lands, so exiting the screen is safe.
                var cancelRequested by remember { mutableStateOf(false) }
                CircularProgressIndicator()
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = if (cancelRequested) stringResource(R.string.create_group_canceling)
                    else dkgStatusText(state.update),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(24.dp))
                if (cancelRequested) {
                    OutlinedButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.create_group_leave))
                    }
                } else {
                    OutlinedButton(
                        onClick = {
                            cancelRequested = true
                            onCancel()
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(stringResource(R.string.create_group_cancel))
                    }
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
