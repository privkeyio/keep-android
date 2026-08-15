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
import io.privkey.keep.uniffi.DkgProgressUpdate
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher

private const val MAX_PARTICIPANTS = 8
private const val MIN_THRESHOLD = 2
private const val MAX_INVITE_LENGTH = 8192

private data class Invite(
    val secret: String,
    val name: String,
    val threshold: Int,
    val participants: Int,
    val relays: List<String>
)

private fun secureRandomHex(byteCount: Int): String {
    val bytes = ByteArray(byteCount)
    SecureRandom().nextBytes(bytes)
    val hex = "0123456789abcdef"
    val out = CharArray(byteCount * 2)
    for (i in bytes.indices) {
        val b = bytes[i].toInt() and 0xFF
        out[i * 2] = hex[b ushr 4]
        out[i * 2 + 1] = hex[b and 0x0F]
    }
    Arrays.fill(bytes, 0.toByte())
    val result = String(out)
    Arrays.fill(out, '0')
    return result
}

private fun isHex64(s: String): Boolean =
    s.length == 64 && s.all { it in '0'..'9' || it in 'a'..'f' }

internal fun isValidInvite(data: String): Boolean {
    if (data.length > MAX_INVITE_LENGTH) return false
    return try {
        val obj = JSONObject(data.trim())
        val threshold = obj.optInt("threshold", -1)
        val participants = obj.optInt("participants", -1)
        obj.optInt("v", -1) == 1 &&
            isHex64(obj.optString("secret", "")) &&
            participants in MIN_THRESHOLD..MAX_PARTICIPANTS &&
            threshold in MIN_THRESHOLD..participants
    } catch (_: Exception) {
        false
    } catch (_: StackOverflowError) {
        false
    }
}

private fun parseInvite(data: String): Invite? {
    if (!isValidInvite(data)) return null
    return try {
        val obj = JSONObject(data.trim())
        val relaysJson = obj.optJSONArray("relays") ?: JSONArray()
        val relays = (0 until relaysJson.length()).mapNotNull { relaysJson.optString(it, null) }
        Invite(
            secret = obj.getString("secret"),
            name = obj.optString("name", ""),
            threshold = obj.getInt("threshold"),
            participants = obj.getInt("participants"),
            relays = relays
        )
    } catch (_: Exception) {
        null
    }
}

private fun buildInviteJson(
    secret: String,
    name: String,
    threshold: Int,
    participants: Int,
    relays: List<String>
): String {
    val obj = JSONObject()
    obj.put("v", 1)
    obj.put("secret", secret)
    obj.put("name", name)
    obj.put("threshold", threshold)
    obj.put("participants", participants)
    obj.put("relays", JSONArray(relays))
    return obj.toString()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateGroupScreen(
    relays: List<String>,
    onCreateGroup: (config: DkgConfig, name: String, cipher: Cipher) -> Unit,
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
        DkgRunView(state = createGroupState, onDismiss = onDismiss)
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
            JoinGroupMode(runDkg = runDkg)
        } else {
            StartGroupMode(relays = relays, runDkg = runDkg)
        }

        Spacer(modifier = Modifier.height(24.dp))

        OutlinedButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.create_group_cancel))
        }
    }
}

@Composable
private fun StartGroupMode(
    relays: List<String>,
    runDkg: (DkgConfig, String, (String) -> Unit) -> Unit
) {
    val defaultName = stringResource(R.string.create_group_default_name)
    var name by remember { mutableStateOf(defaultName) }
    var threshold by remember { mutableStateOf(2) }
    var participants by remember { mutableStateOf(3) }
    var invite by remember { mutableStateOf<String?>(null) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    if (invite == null) {
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

        Button(
            onClick = {
                val secret = secureRandomHex(32)
                invite = buildInviteJson(secret, name, threshold, participants, relays)
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = relays.isNotEmpty()
        ) {
            Text(stringResource(R.string.create_group_create_invite))
        }

        if (relays.isEmpty()) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.create_group_no_relays),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }
    } else {
        val currentInvite = invite!!
        val parsed = parseInvite(currentInvite)!!

        QrCodeDisplay(
            data = currentInvite,
            label = stringResource(R.string.create_group_invite_qr_label)
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = stringResource(R.string.create_group_creator_summary, parsed.participants),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(24.dp))

        errorMessage?.let {
            StatusCard(
                text = it,
                containerColor = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer
            )
            Spacer(modifier = Modifier.height(16.dp))
        }

        Button(
            onClick = {
                errorMessage = null
                val config = DkgConfig(
                    groupName = parsed.name,
                    threshold = parsed.threshold.toUShort(),
                    participants = parsed.participants.toUShort(),
                    ourIndex = 1u,
                    relays = parsed.relays,
                    sessionSecret = parsed.secret
                )
                runDkg(config, parsed.name) { errorMessage = it }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.create_group_start_dkg))
        }
    }
}

@Composable
private fun JoinGroupMode(
    runDkg: (DkgConfig, String, (String) -> Unit) -> Unit
) {
    var showScanner by remember { mutableStateOf(false) }
    var invite by remember { mutableStateOf<Invite?>(null) }
    var myIndex by remember { mutableStateOf(2) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    val scannerTitle = stringResource(R.string.create_group_scan_title)

    if (showScanner) {
        QrScannerScreen(
            onCodeScanned = { code ->
                invite = parseInvite(code)?.also { myIndex = 2 }
                showScanner = false
            },
            onDismiss = { showScanner = false },
            validator = ::isValidInvite,
            title = scannerTitle
        )
        return
    }

    val currentInvite = invite
    if (currentInvite == null) {
        Text(
            text = stringResource(R.string.create_group_join_instructions),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = { showScanner = true }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.create_group_scan_invite))
        }
    } else {
        Text(
            text = stringResource(
                R.string.create_group_joiner_summary,
                currentInvite.threshold,
                currentInvite.participants
            ),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(16.dp))

        Stepper(
            label = stringResource(R.string.create_group_my_number_label, myIndex),
            onDecrement = { if (myIndex > 2) myIndex-- },
            onIncrement = { if (myIndex < currentInvite.participants) myIndex++ },
            canDecrement = myIndex > 2,
            canIncrement = myIndex < currentInvite.participants
        )

        Spacer(modifier = Modifier.height(24.dp))

        errorMessage?.let {
            StatusCard(
                text = it,
                containerColor = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer
            )
            Spacer(modifier = Modifier.height(16.dp))
        }

        Button(
            onClick = {
                errorMessage = null
                val config = DkgConfig(
                    groupName = currentInvite.name,
                    threshold = currentInvite.threshold.toUShort(),
                    participants = currentInvite.participants.toUShort(),
                    ourIndex = myIndex.toUShort(),
                    relays = currentInvite.relays,
                    sessionSecret = currentInvite.secret
                )
                runDkg(config, currentInvite.name) { errorMessage = it }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.create_group_join_dkg))
        }
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
    is DkgProgressUpdate.Finalizing -> stringResource(R.string.create_group_status_finalizing)
    is DkgProgressUpdate.Complete -> stringResource(R.string.create_group_status_finalizing)
    is DkgProgressUpdate.Failed -> update.reason
}
