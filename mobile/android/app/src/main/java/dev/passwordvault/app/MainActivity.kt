package dev.passwordvault.app

import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.passwordvault.app.data.VaultRepository
import dev.passwordvault.app.data.VaultState
import dev.passwordvault.app.ui.MainScreen
import dev.passwordvault.app.ui.theme.VaultTheme
import dev.passwordvault.app.ui.unlock.RecoveryCodeScreen
import dev.passwordvault.app.ui.unlock.UnlockScreen
import dev.passwordvault.app.ui.unlock.WelcomeScreen

/** FragmentActivity because BiometricPrompt needs one. */
class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, screen recording or previews in Recents. Debug builds
        // let the UI tests (mobile/android/app/src/androidTest) turn it off.
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        if (!(debuggable && intent.getBooleanExtra(EXTRA_ALLOW_SCREENSHOTS, false))) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        enableEdgeToEdge()
        val vault = (application as VaultApp).vault
        setContent {
            var dynamic by remember { mutableStateOf(vault.settings.dynamicColor) }
            VaultTheme(dynamicColor = dynamic) {
                AppRoot(vault, onDynamicColor = { vault.settings.dynamicColor = it; dynamic = it })
            }
        }
    }

    companion object {
        const val EXTRA_ALLOW_SCREENSHOTS = "dev.passwordvault.app.ALLOW_SCREENSHOTS"
    }
}

@Composable
private fun AppRoot(vault: VaultRepository, onDynamicColor: (Boolean) -> Unit) {
    val state by vault.state.collectAsStateWithLifecycle()
    // Shown once right after creating a vault, before the main screen.
    var recoveryCode by rememberSaveable { mutableStateOf<String?>(null) }
    when {
        recoveryCode != null -> RecoveryCodeScreen(vault, recoveryCode!!) { recoveryCode = null }
        state is VaultState.NoVault -> WelcomeScreen(vault, onCreated = { recoveryCode = it })
        state is VaultState.Locked -> UnlockScreen(vault, state as VaultState.Locked)
        else -> MainScreen(vault, onDynamicColor)
    }
}
