package dev.passwordvault.app.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Inventory2
import androidx.compose.material.icons.outlined.Password
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Timer
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteScaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.vector.ImageVector
import dev.passwordvault.app.data.VaultRepository
import dev.passwordvault.app.ui.codes.CodesScreen
import dev.passwordvault.app.ui.generator.GeneratorScreen
import dev.passwordvault.app.ui.items.ItemsScreen
import dev.passwordvault.app.ui.settings.SettingsScreen

private enum class Tab(val label: String, val icon: ImageVector) {
    Items("Items", Icons.Outlined.Inventory2),
    Codes("Codes", Icons.Outlined.Timer),
    Generator("Generator", Icons.Outlined.Password),
    Settings("Settings", Icons.Outlined.Settings),
}

/**
 * The unlocked app. NavigationSuiteScaffold picks a bottom bar on phones,
 * a navigation rail on tablets and open foldables, and a drawer on large
 * windows, from the window size class.
 */
@Composable
fun MainScreen(vault: VaultRepository, onDynamicColor: (Boolean) -> Unit) {
    var tab by rememberSaveable { mutableStateOf(Tab.Items) }
    NavigationSuiteScaffold(
        navigationSuiteItems = {
            Tab.entries.forEach { t ->
                item(
                    selected = t == tab,
                    onClick = { tab = t },
                    icon = { Icon(t.icon, contentDescription = null) },
                    label = { Text(t.label) },
                )
            }
        },
    ) {
        when (tab) {
            Tab.Items -> ItemsScreen(vault)
            Tab.Codes -> CodesScreen(vault)
            Tab.Generator -> GeneratorScreen(vault)
            Tab.Settings -> SettingsScreen(vault, onDynamicColor)
        }
    }
}
