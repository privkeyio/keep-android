package io.privkey.keep.ui.components

import android.widget.Toast
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import io.privkey.keep.R
import io.privkey.keep.copyPublicText
import io.privkey.keep.copySensitiveText
import io.privkey.keep.ui.theme.Dimens
import io.privkey.keep.ui.theme.KeepMono

// A labeled value with a copy affordance. Reuses the app's clipboard helpers
// (sensitive copies auto-clear after a delay); never reimplements clipboard logic.
@Composable
fun CopyableValue(
    label: String,
    value: String,
    sensitive: Boolean,
    modifier: Modifier = Modifier,
    displayValue: String = value,
    mono: Boolean = false
) {
    val context = LocalContext.current
    val copiedMessage = stringResource(R.string.copied_to_clipboard)
    Row(modifier = modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(Dimens.space2))
            val bodyStyle = MaterialTheme.typography.bodyMedium
            Text(displayValue, style = if (mono) bodyStyle.copy(fontFamily = KeepMono) else bodyStyle)
        }
        Spacer(Modifier.width(Dimens.space8))
        IconButton(onClick = {
            if (sensitive) copySensitiveText(context, value) else copyPublicText(context, value)
            Toast.makeText(context, copiedMessage, Toast.LENGTH_SHORT).show()
        }) {
            Icon(Icons.Default.ContentCopy, contentDescription = stringResource(R.string.copy))
        }
    }
}
