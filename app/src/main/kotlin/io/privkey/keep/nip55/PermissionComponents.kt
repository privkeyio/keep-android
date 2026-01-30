package io.privkey.keep.nip55

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreeStateToggle(
    currentDecision: PermissionDecision,
    onDecisionChange: (PermissionDecision) -> Unit,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        PermissionDecision.entries.forEach { decision ->
            val isSelected = decision == currentDecision
            DecisionChip(
                decision = decision,
                isSelected = isSelected,
                onClick = { if (!isSelected) onDecisionChange(decision) },
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DecisionChip(
    decision: PermissionDecision,
    isSelected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = MaterialTheme.colorScheme
    val (containerColor, contentColor) = if (isSelected) {
        when (decision) {
            PermissionDecision.ALLOW -> colors.primaryContainer to colors.onPrimaryContainer
            PermissionDecision.DENY -> colors.errorContainer to colors.onErrorContainer
            PermissionDecision.ASK -> colors.tertiaryContainer to colors.onTertiaryContainer
        }
    } else {
        colors.surfaceVariant to colors.onSurfaceVariant
    }

    FilterChip(
        selected = isSelected,
        onClick = onClick,
        label = { Text(stringResource(decision.displayNameRes)) },
        modifier = modifier,
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = containerColor,
            selectedLabelColor = contentColor
        )
    )
}
