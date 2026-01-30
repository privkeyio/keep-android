package io.privkey.keep.nip55

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreeStateToggle(
    currentDecision: PermissionDecision,
    onDecisionChange: (PermissionDecision) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current

    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        PermissionDecision.entries.forEach { decision ->
            val isSelected = decision == currentDecision
            val containerColor = when {
                !isSelected -> MaterialTheme.colorScheme.surfaceVariant
                decision == PermissionDecision.ALLOW -> MaterialTheme.colorScheme.primaryContainer
                decision == PermissionDecision.DENY -> MaterialTheme.colorScheme.errorContainer
                else -> MaterialTheme.colorScheme.tertiaryContainer
            }
            val contentColor = when {
                !isSelected -> MaterialTheme.colorScheme.onSurfaceVariant
                decision == PermissionDecision.ALLOW -> MaterialTheme.colorScheme.onPrimaryContainer
                decision == PermissionDecision.DENY -> MaterialTheme.colorScheme.onErrorContainer
                else -> MaterialTheme.colorScheme.onTertiaryContainer
            }

            FilterChip(
                selected = isSelected,
                onClick = { if (!isSelected) onDecisionChange(decision) },
                label = { Text(context.getString(decision.displayNameRes)) },
                modifier = Modifier.weight(1f),
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = containerColor,
                    selectedLabelColor = contentColor
                )
            )
        }
    }
}
