package dev.passwordvault.app.ui.unlock

import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import dev.passwordvault.app.data.QuickUnlock
import dev.passwordvault.app.data.VaultRepository
import dev.passwordvault.app.data.VaultState
import dev.passwordvault.app.ui.components.SecureClipboard
import dev.passwordvault.app.ui.theme.Mono
import kotlinx.coroutines.launch

fun Context.findActivity(): FragmentActivity {
    var c: Context = this
    while (c is ContextWrapper) {
        if (c is FragmentActivity) return c
        c = c.baseContext
    }
    error("no activity")
}

/** The app icon: a white keyhole on the signal-red tile. */
@Composable
fun AppIcon(size: androidx.compose.ui.unit.Dp = 88.dp) {
    Box(
        Modifier
            .size(size)
            .clip(RoundedCornerShape(size * 0.32f))
            .background(Brush.linearGradient(listOf(Color(0xFFEE3B36), Color(0xFFB5161B)))),
        contentAlignment = Alignment.Center,
    ) {
        androidx.compose.foundation.Canvas(Modifier.size(size * 0.5f)) {
            val s = this.size.width / 40f
            drawCircle(Color.White, radius = 7f * s, center = androidx.compose.ui.geometry.Offset(20f * s, 15f * s))
            val p = Path().apply {
                moveTo(16f * s, 19f * s); lineTo(14f * s, 32f * s); lineTo(26f * s, 32f * s); lineTo(24f * s, 19f * s); close()
            }
            drawPath(p, Color.White)
        }
    }
}

/** Centred, width-limited column so phones, tablets and foldables all look right. */
@Composable
private fun CenteredPage(content: @Composable () -> Unit) {
    Box(
        Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).safeDrawingPadding().imePadding(),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            Modifier.widthIn(max = 460.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) { content() }
    }
}

@Composable
fun SecretField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    imeAction: ImeAction = ImeAction.Done,
    onDone: () -> Unit = {},
) {
    var shown by remember { mutableStateOf(false) }
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        singleLine = true,
        visualTransformation = if (shown) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = imeAction, autoCorrectEnabled = false),
        keyboardActions = KeyboardActions(onDone = { onDone() }, onGo = { onDone() }),
        trailingIcon = {
            IconButton(onClick = { shown = !shown }) {
                Icon(
                    if (shown) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                    contentDescription = if (shown) "Hide" else "Show",
                )
            }
        },
        shape = MaterialTheme.shapes.medium,
        modifier = modifier.fillMaxWidth(),
    )
}

@Composable
fun WelcomeScreen(vault: VaultRepository, onCreated: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var creating by rememberSaveable { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        context.contentResolver.takePersistableUriPermission(
            uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
        )
        scope.launch {
            error = runCatching { vault.join(uri) }.exceptionOrNull()?.let { it.message ?: "That file could not be opened." }
        }
    }
    CenteredPage {
        Spacer(Modifier.height(32.dp))
        AppIcon()
        Spacer(Modifier.height(24.dp))
        Text("Secret Vault", style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        Text(
            "Your passwords, cards and one-time codes, encrypted on this device. Nothing is sent to a server.",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(32.dp))
        if (!creating) {
            Button(onClick = { creating = true }, modifier = Modifier.fillMaxWidth().height(56.dp)) {
                Text("Create a new vault")
            }
            Spacer(Modifier.height(12.dp))
            OutlinedButton(onClick = { pick.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth().height(56.dp)) {
                Text("Use a vault from my computer")
            }
            Spacer(Modifier.height(12.dp))
            Text(
                "To use your desktop vault here, turn on Sync on your computer, then pick the synced .svault file in Google Drive, OneDrive or Dropbox.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        } else {
            SecretField(password, { password = it }, "Master password", imeAction = ImeAction.Next)
            Spacer(Modifier.height(12.dp))
            SecretField(confirm, { confirm = it }, "Type it again")
            Spacer(Modifier.height(8.dp))
            Text(
                "Use at least 12 characters, or four random words. Nobody can recover this password for you; the recovery code on the next screen is the only other way in.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(20.dp))
            Button(
                enabled = !busy && password.length >= 8,
                onClick = {
                    if (password != confirm) {
                        error = "The two passwords are different."
                        return@Button
                    }
                    busy = true
                    scope.launch {
                        runCatching { vault.create(password) }
                            .onSuccess { password = ""; confirm = ""; onCreated(it) }
                            .onFailure { error = it.message }
                        busy = false
                    }
                },
                modifier = Modifier.fillMaxWidth().height(56.dp),
            ) {
                if (busy) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp) else Text("Create vault")
            }
            TextButton(onClick = { creating = false }) { Text("Back") }
        }
        error?.let {
            Spacer(Modifier.height(12.dp))
            Text(it, color = MaterialTheme.colorScheme.error, textAlign = TextAlign.Center)
        }
    }
}

@Composable
fun RecoveryCodeScreen(vault: VaultRepository, code: String, onDone: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var saved by rememberSaveable { mutableStateOf(false) }
    CenteredPage {
        Spacer(Modifier.height(24.dp))
        Text("Your recovery code", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        Text(
            "If you forget your master password, this code is the only way back in. Write it on paper and keep it somewhere safe. It is shown only now.",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(24.dp))
        Surface(shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.primaryContainer, modifier = Modifier.fillMaxWidth()) {
            Text(
                code,
                fontFamily = Mono,
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(24.dp),
            )
        }
        TextButton(onClick = {
            SecureClipboard.copy(context, "Recovery code", code, sensitive = true, clearAfterSeconds = 60)
        }) { Text("Copy (cleared in 60 s)") }
        // The whole row toggles, not just the small box.
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().toggleable(value = saved, role = Role.Checkbox, onValueChange = { saved = it }),
        ) {
            Checkbox(checked = saved, onCheckedChange = null)
            Text("I wrote it down", style = MaterialTheme.typography.bodyLarge)
        }
        Spacer(Modifier.height(16.dp))
        Button(
            enabled = saved,
            onClick = {
                scope.launch {
                    if (vault.quickUnlock.hardwareReady()) {
                        runCatching { vault.enableQuickUnlock(context.findActivity()) }
                    }
                    onDone()
                }
            },
            modifier = Modifier.fillMaxWidth().height(56.dp),
        ) { Text(if (vault.quickUnlock.hardwareReady()) "Continue and set up fingerprint unlock" else "Continue") }
        if (vault.quickUnlock.hardwareReady()) {
            TextButton(enabled = saved, onClick = onDone) { Text("Continue without fingerprint unlock") }
        }
    }
}

@Composable
fun UnlockScreen(vault: VaultRepository, state: VaultState.Locked) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var secret by remember { mutableStateOf("") }
    var recovery by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun biometric() {
        scope.launch {
            busy = true
            runCatching { vault.unlockBiometric(context.findActivity()) }
                .onFailure { if (it !is QuickUnlock.Cancelled) error = it.message }
            busy = false
        }
    }

    fun submit() {
        if (secret.isEmpty() || busy) return
        busy = true
        error = null
        scope.launch {
            val r = runCatching { if (recovery) vault.unlockRecovery(secret) else vault.unlockPassword(secret) }
            busy = false
            r.onSuccess { secret = "" }.onFailure { error = it.message }
        }
    }

    // Offer the fingerprint straight away, as the system apps do.
    LaunchedEffect(state.quickUnlock) { if (state.quickUnlock) biometric() }

    CenteredPage {
        Spacer(Modifier.height(48.dp))
        AppIcon()
        Spacer(Modifier.height(20.dp))
        Text("Secret Vault", style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.SemiBold)
        Text("Locked", style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(32.dp))
        if (vault.quickUnlock.isEnabled && vault.fullUnlockDue()) {
            Text(
                "It's been 14 days: enter your master password once to keep fingerprint unlock on.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(12.dp))
        }
        SecretField(
            secret,
            { secret = it },
            if (recovery) "Recovery code" else "Master password",
            onDone = ::submit,
        )
        Spacer(Modifier.height(16.dp))
        Button(onClick = ::submit, enabled = !busy && secret.isNotEmpty(), modifier = Modifier.fillMaxWidth().height(56.dp)) {
            if (busy) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp) else Text("Unlock")
        }
        if (state.quickUnlock) {
            Spacer(Modifier.height(12.dp))
            FilledTonalButton(onClick = ::biometric, enabled = !busy, modifier = Modifier.fillMaxWidth().height(56.dp)) {
                Icon(Icons.Outlined.Fingerprint, contentDescription = null)
                Spacer(Modifier.size(8.dp))
                Text("Use fingerprint or face")
            }
        }
        TextButton(onClick = { recovery = !recovery; secret = "" }) {
            Text(if (recovery) "Use master password" else "Use recovery code")
        }
        if (!state.hasPassword && !recovery) {
            Text(
                "This vault has no password-only unlock method, so use the recovery code here or add a password on your computer.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
        error?.let {
            Spacer(Modifier.height(12.dp))
            Text(it, color = MaterialTheme.colorScheme.error, textAlign = TextAlign.Center)
        }
    }
}
