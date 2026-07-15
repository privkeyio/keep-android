package io.privkey.keep.nip55

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.privkey.keep.R
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.storage.SignPolicyStore
import io.privkey.keep.ui.components.SignPolicyOptionRow
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SignPolicyScreen(
    signPolicyStore: SignPolicyStore,
    onDismiss: () -> Unit
) {
    var selectedPolicy by remember { mutableStateOf(SignPolicy.MANUAL) }
    var userInteracted by remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        val loaded = withContext(Dispatchers.IO) { signPolicyStore.getGlobalPolicy() }
        if (!userInteracted) selectedPolicy = loaded
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.sign_policy)) },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = stringResource(R.string.sign_policy_global_setting),
                style = MaterialTheme.typography.titleMedium
            )

            SignPolicy.entries.forEach { policy ->
                SignPolicyOptionRow(
                    policy = policy,
                    isSelected = selectedPolicy == policy,
                    onSelected = {
                        userInteracted = true
                        selectedPolicy = policy
                        coroutineScope.launch {
                            withContext(Dispatchers.IO) {
                                signPolicyStore.setGlobalPolicy(policy)
                            }
                        }
                    }
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppSignPolicySelector(
    currentOverride: Int?,
    globalPolicy: SignPolicy,
    onOverrideChange: (Int?) -> Unit,
    modifier: Modifier = Modifier
) {
    var expanded by remember { mutableStateOf(false) }
    val globalPolicyName = stringResource(globalPolicy.displayNameRes)
    val displayText = if (currentOverride == null) {
        stringResource(R.string.sign_policy_use_global) + " ($globalPolicyName)"
    } else {
        stringResource(SignPolicy.fromOrdinal(currentOverride).displayNameRes)
    }

    Column(modifier = modifier.fillMaxWidth()) {
        Text(
            text = stringResource(R.string.sign_policy_app_override),
            style = MaterialTheme.typography.titleSmall
        )
        Spacer(modifier = Modifier.height(8.dp))

        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = it }
        ) {
            OutlinedTextField(
                value = displayText,
                onValueChange = {},
                readOnly = true,
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier
                    .fillMaxWidth()
                    .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable)
            )

            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false }
            ) {
                DropdownMenuItem(
                    text = {
                        Text(stringResource(R.string.sign_policy_use_global) + " ($globalPolicyName)")
                    },
                    onClick = {
                        onOverrideChange(null)
                        expanded = false
                    }
                )
                SignPolicy.entries.forEach { policy ->
                    DropdownMenuItem(
                        text = { Text(stringResource(policy.displayNameRes)) },
                        onClick = {
                            onOverrideChange(policy.ordinal)
                            expanded = false
                        }
                    )
                }
            }
        }

        currentOverride?.let { ordinal ->
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = stringResource(SignPolicy.fromOrdinal(ordinal).descriptionRes),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
