package io.privkey.keep.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.ui.graphics.vector.ImageVector

sealed class Route(val route: String, val label: String, val icon: ImageVector) {
    data object Home : Route("home", "Home", Icons.Filled.Home)
    data object Apps : Route("apps", "Apps", Icons.Filled.Apps)
    data object Settings : Route("settings", "Settings", Icons.Filled.Settings)
    data object Account : Route("account", "Account", Icons.Filled.AccountCircle)

    companion object {
        val items = listOf(Home, Apps, Settings, Account)
    }
}
