package io.privkey.keep.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.ui.theme.Dimens

@Composable
fun SignPolicyOptionRow(
    policy: SignPolicy,
    isSelected: Boolean,
    onSelected: () -> Unit,
    modifier: Modifier = Modifier
) {
    val borderColor = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline
    KeepCard(
        modifier = modifier.selectable(
            selected = isSelected,
            onClick = onSelected,
            role = Role.RadioButton
        ),
        border = BorderStroke(Dimens.cardBorderWidth, borderColor)
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
