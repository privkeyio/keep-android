package io.privkey.keep.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

@Composable
fun KeepAndroidTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    // Default to the Keep brand palette (dark + green, matching the StartOS Web
    // Admin) rather than wallpaper-derived Material You, so the app is on-brand.
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        else -> KeepDarkColors
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = KeepTypography,
        shapes = KeepShapes,
        content = content
    )
}
