package io.privkey.keep.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// Monospace family for keys, hashes, and other fixed-width identifiers.
val KeepMono = FontFamily.Monospace

// Branded type scale on the system font. Titles and labels carry more weight
// (W600) for a crisp, technical console feel; body sizes are nudged up slightly
// so they stay legible on the dark KeepBg surface.
val KeepTypography = Typography(
    displayLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal,
        fontSize = 57.sp, lineHeight = 64.sp, letterSpacing = (-0.25).sp
    ),
    displayMedium = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal,
        fontSize = 45.sp, lineHeight = 52.sp, letterSpacing = 0.sp
    ),
    displaySmall = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium,
        fontSize = 36.sp, lineHeight = 44.sp, letterSpacing = 0.sp
    ),
    headlineLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 30.sp, lineHeight = 36.sp, letterSpacing = (-0.25).sp
    ),
    headlineMedium = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 26.sp, lineHeight = 32.sp, letterSpacing = (-0.25).sp
    ),
    headlineSmall = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 22.sp, lineHeight = 28.sp, letterSpacing = 0.sp
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp, lineHeight = 26.sp, letterSpacing = 0.sp
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp, lineHeight = 22.sp, letterSpacing = 0.1.sp
    ),
    titleSmall = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.1.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal,
        fontSize = 16.sp, lineHeight = 24.sp, letterSpacing = 0.15.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal,
        fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.2.sp
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal,
        fontSize = 13.sp, lineHeight = 18.sp, letterSpacing = 0.2.sp
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.1.sp
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 12.sp, lineHeight = 16.sp, letterSpacing = 0.5.sp
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 11.sp, lineHeight = 16.sp, letterSpacing = 0.5.sp
    )
)
