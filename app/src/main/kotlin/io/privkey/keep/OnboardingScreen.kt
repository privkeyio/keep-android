package io.privkey.keep

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.storage.SignPolicyStore
import io.privkey.keep.ui.components.KeepCard
import io.privkey.keep.ui.components.KeepScreenScaffold
import io.privkey.keep.ui.theme.Dimens
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun OnboardingScreen(
    signPolicyStore: SignPolicyStore,
    onDone: () -> Unit
) {
    var selectedPolicy by remember { mutableStateOf(SignPolicy.MANUAL) }
    val coroutineScope = rememberCoroutineScope()

    KeepScreenScaffold(title = stringResource(R.string.onboarding_title)) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(Dimens.space16)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(Dimens.space16)
        ) {
            Text(
                text = stringResource(R.string.onboarding_intro),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            OnboardingInfoCard(
                icon = Icons.Filled.Key,
                title = stringResource(R.string.onboarding_frost_title),
                body = stringResource(R.string.onboarding_frost_body)
            )

            OnboardingInfoCard(
                icon = Icons.Filled.CheckCircle,
                title = stringResource(R.string.onboarding_threshold_title),
                body = stringResource(R.string.onboarding_threshold_body)
            )

            OnboardingInfoCard(
                icon = Icons.Filled.Info,
                title = stringResource(R.string.onboarding_nsec_title),
                body = stringResource(R.string.onboarding_nsec_body)
            )

            OnboardingInfoCard(
                icon = Icons.Filled.Warning,
                title = stringResource(R.string.onboarding_backup_title),
                body = stringResource(R.string.onboarding_backup_body)
            )

            Text(
                text = stringResource(R.string.onboarding_sign_policy_heading),
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = stringResource(R.string.onboarding_sign_policy_subheading),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            SignPolicy.entries.forEach { policy ->
                OnboardingPolicyOption(
                    policy = policy,
                    isSelected = selectedPolicy == policy,
                    onClick = {
                        selectedPolicy = policy
                        coroutineScope.launch {
                            withContext(Dispatchers.IO) {
                                signPolicyStore.setGlobalPolicy(policy)
                            }
                        }
                    }
                )
            }

            Spacer(Modifier.height(Dimens.space4))
            Button(
                onClick = onDone,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.onboarding_get_started))
            }
        }
    }
}

@Composable
private fun OnboardingInfoCard(
    icon: ImageVector,
    title: String,
    body: String
) {
    KeepCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(24.dp)
            )
            Spacer(Modifier.width(Dimens.space12))
            Text(title, style = MaterialTheme.typography.titleMedium)
        }
        Spacer(Modifier.height(Dimens.space8))
        Text(
            body,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun OnboardingPolicyOption(
    policy: SignPolicy,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    val borderColor = if (isSelected) MaterialTheme.colorScheme.primary else Color.Transparent
    KeepCard(
        modifier = Modifier.border(
            Dimens.cardBorderWidth,
            borderColor,
            RoundedCornerShape(Dimens.space12)
        ).selectable(
            selected = isSelected,
            onClick = onClick,
            role = Role.RadioButton
        )
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = isSelected, onClick = null)
            Spacer(Modifier.width(Dimens.space16))
            Column {
                Text(
                    stringResource(policy.displayNameRes),
                    style = MaterialTheme.typography.titleMedium
                )
                Spacer(Modifier.height(Dimens.space4))
                Text(
                    stringResource(policy.descriptionRes),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
