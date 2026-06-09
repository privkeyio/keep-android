package io.privkey.keep.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import io.privkey.keep.ui.theme.Dimens

// Flat, outlined card: brand surface + 1dp border, no shadow. The single place
// the card convention is defined so every screen looks consistent.
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeepCard(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    contentPadding: PaddingValues = PaddingValues(Dimens.cardPadding),
    content: @Composable ColumnScope.() -> Unit
) {
    val colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    val border = BorderStroke(Dimens.cardBorderWidth, MaterialTheme.colorScheme.outline)
    val elevation = CardDefaults.cardElevation(defaultElevation = Dimens.cardElevation)
    if (onClick != null) {
        Card(onClick = onClick, modifier = modifier.fillMaxWidth(), colors = colors, border = border, elevation = elevation) {
            Column(Modifier.padding(contentPadding), content = content)
        }
    } else {
        Card(modifier = modifier.fillMaxWidth(), colors = colors, border = border, elevation = elevation) {
            Column(Modifier.padding(contentPadding), content = content)
        }
    }
}

@Composable
fun KeepSectionCard(
    modifier: Modifier = Modifier,
    title: String? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    KeepCard(modifier = modifier) {
        if (title != null) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(Dimens.cardInnerGap))
        }
        content()
    }
}
