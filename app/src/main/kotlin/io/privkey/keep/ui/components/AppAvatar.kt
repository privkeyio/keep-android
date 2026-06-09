package io.privkey.keep.ui.components

import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import io.privkey.keep.R
import io.privkey.keep.ui.theme.Dimens

// Curated, on-brand avatar backgrounds (greens/teals/blues/neutrals that read on
// the dark surface). Keys map deterministically into this palette.
private val AVATAR_PALETTE = listOf(
    Color(0xFF2F8F5B), Color(0xFF3FB950), Color(0xFF2EA043),
    Color(0xFF1F6FEB), Color(0xFF388BFD), Color(0xFF6E40C9),
    Color(0xFFBF8700), Color(0xFF1B7C83), Color(0xFF57606A)
)

// Avatar for a connected app or NIP-46 client: the installed app icon when
// available, otherwise a deterministic colored monogram derived from the name
// (or key). Replaces the generic cloud icon for keyed clients.
@Composable
fun AppAvatar(
    key: String,
    name: String?,
    modifier: Modifier = Modifier,
    drawable: Drawable? = null,
    unverified: Boolean = false,
    size: Dp = Dimens.avatarSize
) {
    val shape = RoundedCornerShape(8.dp)
    val sizePx = with(LocalDensity.current) { size.roundToPx() }
    when {
        drawable != null -> {
            val bitmap = remember(drawable, sizePx) { drawable.toBitmap(sizePx, sizePx).asImageBitmap() }
            Image(
                bitmap = bitmap,
                contentDescription = null,
                modifier = modifier
                    .size(size)
                    .clip(shape)
            )
        }
        unverified -> {
            Box(
                modifier = modifier
                    .size(size)
                    .clip(shape)
                    .background(MaterialTheme.colorScheme.errorContainer),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Default.Warning,
                    contentDescription = stringResource(R.string.connected_app_unverified),
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(size * 0.6f)
                )
            }
        }
        else -> {
            Box(
                modifier = modifier
                    .size(size)
                    .clip(shape)
                    .background(avatarColor(key)),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = monogram(name, key),
                    style = MaterialTheme.typography.titleMedium,
                    color = Color.White
                )
            }
        }
    }
}

private fun avatarColor(key: String): Color {
    val idx = (key.hashCode() and Int.MAX_VALUE) % AVATAR_PALETTE.size
    return AVATAR_PALETTE[idx]
}

private fun monogram(name: String?, key: String): String {
    val basis = name?.trim()?.takeIf { it.isNotBlank() && !it.equals("Unknown", ignoreCase = true) }
    if (basis != null) {
        val parts = basis.split(Regex("\\s+")).filter { it.isNotBlank() }
        return if (parts.size >= 2) {
            "${parts[0].first()}${parts[1].first()}".uppercase()
        } else {
            basis.take(2).uppercase()
        }
    }
    return key.removePrefix("nip46:").take(2).uppercase()
}
