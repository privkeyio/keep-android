package io.privkey.keep.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.graphics.Color

// Keep brand palette, matching the StartOS Web Admin (dark with green accents).
val KeepGreen = Color(0xFF3FB950)
val KeepAccent = Color(0xFF2F8F5B)
val KeepAccentSoft = Color(0xFF1C3A2B)
val KeepBg = Color(0xFF0F1217)
val KeepSurface = Color(0xFF171C24)
val KeepSurfaceVariant = Color(0xFF1D232D)
val KeepBorder = Color(0xFF262E3A)
val KeepText = Color(0xFFE6EDF3)
val KeepMuted = Color(0xFF9AA4B2)
val KeepWarn = Color(0xFFE3B341)
val KeepError = Color(0xFFE5534B)

val KeepDarkColors = darkColorScheme(
    primary = KeepGreen,
    onPrimary = Color(0xFF06140C),
    primaryContainer = KeepAccentSoft,
    onPrimaryContainer = Color(0xFF7EE0A0),
    secondary = KeepAccent,
    onSecondary = Color(0xFF06140C),
    secondaryContainer = KeepAccentSoft,
    onSecondaryContainer = Color(0xFF7EE0A0),
    tertiary = KeepWarn,
    onTertiary = Color(0xFF1A1402),
    background = KeepBg,
    onBackground = KeepText,
    surface = KeepSurface,
    onSurface = KeepText,
    surfaceVariant = KeepSurfaceVariant,
    onSurfaceVariant = KeepMuted,
    outline = KeepBorder,
    outlineVariant = Color(0xFF1F2630),
    error = KeepError,
    onError = Color(0xFF2A0907),
)
