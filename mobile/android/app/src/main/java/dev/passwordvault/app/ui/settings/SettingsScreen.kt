package dev.passwordvault.app.ui.settings

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings as AndroidSettings
import android.view.autofill.AutofillManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.passwordvault.app.data.VaultRepository
import dev.passwordvault.app.ui.components.SectionLabel
import dev.passwordvault.app.ui.components.segmentShape
import dev.passwordvault.app.ui.unlock.SecretField
import dev.passwordvault.app.ui.unlock.findActivity
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.launch

@Composable
fun SettingsScreen(vault: VaultRepository, onDynamicColor: (Boolean) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val sync by vault.sync.collectAsStateWithLifecycle()
    var quick by remember { mutableStateOf(vault.quickUnlock.isEnabled) }
    var autoLock by remember { mutableIntStateOf(vault.settings.autoLockSeconds) }
    var clip by remember { mutableIntStateOf(vault.settings.clipboardSeconds) }
    var dynamic by remember { mutableStateOf(vault.settings.dynamicColor) }
    var message by remember { mutableStateOf<String?>(null) }
    var askPassword by remember { mutableStateOf(false) }
    var confirmRemove by remember { mutableStateOf(false) }

    fun persist(uri: Uri?) {
        uri ?: return
        context.contentResolver.takePersistableUriPermission(
            uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
        )
    }
    val createSync = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        persist(uri)
        if (uri != null) scope.launch { runCatching { vault.setSyncFile(uri, create = true) }.onFailure { message = it.message } }
    }
    val openSync = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        persist(uri)
        if (uri != null) scope.launch { runCatching { vault.setSyncFile(uri, create = false) }.onFailure { message = it.message } }
    }

    Column(
        Modifier.fillMaxSize().statusBarsPadding().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(Modifier.widthIn(max = 640.dp).fillMaxWidth()) {
            Text("Settings", style = MaterialTheme.typography.headlineMedium, modifier = Modifier.padding(start = 8.dp, top = 16.dp))
            message?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(8.dp)) }

            SectionLabel("Unlocking")
            Group(3) { i, shape ->
                when (i) {
                    0 -> SwitchRow(
                        "Fingerprint or face unlock",
                        if (vault.quickUnlock.hardwareReady()) "Your master password is still needed every 14 days."
                        else "Set up a fingerprint or face in Android settings first.",
                        quick, shape,
                    ) { on ->
                        if (on) {
                            scope.launch {
                                runCatching { vault.enableQuickUnlock(context.findActivity()) }
                                    .onSuccess { quick = true; message = null }
                                    .onFailure { message = it.message }
                            }
                        } else {
                            vault.quickUnlock.disable()
                            quick = false
                        }
                    }
                    1 -> ChoiceRow(
                        "Lock after", autoLockLabel(autoLock), shape,
                        listOf(0, 60, 300, 900, 3600).map { autoLockLabel(it) to it },
                    ) { autoLock = it; vault.settings.autoLockSeconds = it }
                    else -> ChoiceRow(
                        "Clear copied passwords after", "$clip seconds", shape,
                        listOf(30, 60, 120).map { "$it seconds" to it },
                    ) { clip = it; vault.settings.clipboardSeconds = it }
                }
            }

            SectionLabel("Sync")
            Group(if (sync.enabled) 3 else 2) { i, shape ->
                when {
                    !sync.enabled && i == 0 -> ActionRow(
                        "Sync with my computer",
                        "Pick the vault file your computer syncs in Google Drive, OneDrive or Dropbox.",
                        shape,
                    ) { openSync.launch(arrayOf("*/*")) }
                    !sync.enabled -> ActionRow(
                        "Start a new synced copy",
                        "Save this vault into a cloud folder, then join it from your computer.",
                        shape,
                    ) { createSync.launch("vault.svault") }
                    i == 0 -> InfoRow(
                        "Synced",
                        when {
                            sync.error != null -> sync.error!!
                            sync.lastSyncMillis > 0 -> "Last merged " + DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(sync.lastSyncMillis)) +
                                if (sync.conflicts > 0) " · ${sync.conflicts} conflict copies made" else ""
                            else -> "Waiting for the first merge"
                        },
                        shape,
                    )
                    i == 1 -> ActionRow(if (sync.needsPassword) "Merge with master password" else "Sync now", null, shape) {
                        if (sync.needsPassword) askPassword = true else scope.launch { vault.syncNow() }
                    }
                    else -> ActionRow("Stop syncing", "The file in the cloud folder stays where it is.", shape) {
                        scope.launch { vault.setSyncFile(null, create = false) }
                    }
                }
            }

            SectionLabel("Autofill")
            val afm = context.getSystemService(AutofillManager::class.java)
            val isDefault = afm?.hasEnabledAutofillServices() == true
            Group(1) { _, shape ->
                ActionRow(
                    if (isDefault) "Secret Vault fills passwords" else "Use Secret Vault for autofill",
                    if (isDefault) "Logins are offered only on the sites they are bound to."
                    else "Opens Android's autofill settings. Choose Secret Vault.",
                    shape,
                ) {
                    val intent = Intent(AndroidSettings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
                        .setData(Uri.parse("package:${context.packageName}"))
                    runCatching { context.startActivity(intent) }
                }
            }

            SectionLabel("Unlock methods")
            val slots = remember { vault.slots() }
            Group(slots.size) { i, shape ->
                val s = slots[i]
                val kind = s.factor.replaceFirstChar { it.uppercase() }
                // A slot without its own name is labelled with its kind; don't say it twice.
                val named = s.label.isNotBlank() && !s.label.equals(s.factor, ignoreCase = true)
                val where = if (s.usableHere) "Works on this device" else "Works on the computer that added it"
                InfoRow(if (named) s.label else kind, if (named) "$kind · $where" else where, shape)
            }
            Text(
                "Add or remove unlock methods in the desktop app; they sync to this device.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(8.dp),
            )

            SectionLabel("Appearance")
            Group(1) { _, shape ->
                SwitchRow(
                    "Use wallpaper colours",
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) "Material You colours instead of the vault's blue." else "Needs Android 12 or later.",
                    dynamic, shape,
                ) { dynamic = it; onDynamicColor(it) }
            }

            SectionLabel("This phone")
            Group(2) { i, shape ->
                if (i == 0) {
                    ActionRow("Lock now", null, shape) { vault.lock() }
                } else {
                    ActionRow("Remove the vault from this device", "Synced copies and other devices keep theirs.", shape) { confirmRemove = true }
                }
            }
            Spacer(Modifier.size(48.dp))
        }
    }

    if (askPassword) {
        var pw by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { askPassword = false },
            title = { Text("Merge the re-keyed copy") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("An unlock method was revoked on another device. Enter your master password to take the new key.")
                    SecretField(pw, { pw = it }, "Master password")
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    askPassword = false
                    scope.launch { vault.syncNow(pw) }
                }) { Text("Merge") }
            },
            dismissButton = { TextButton(onClick = { askPassword = false }) { Text("Cancel") } },
        )
    }
    if (confirmRemove) {
        AlertDialog(
            onDismissRequest = { confirmRemove = false },
            title = { Text("Remove the vault from this device?") },
            text = { Text("Items that were never synced are lost. Your computer and the synced copy are not changed.") },
            confirmButton = {
                TextButton(onClick = { confirmRemove = false; vault.removeFromDevice() }) {
                    Text("Remove", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { confirmRemove = false }) { Text("Cancel") } },
        )
    }
}

private fun autoLockLabel(s: Int) = when (s) {
    0 -> "Immediately"
    60 -> "1 minute"
    3600 -> "1 hour"
    else -> "${s / 60} minutes"
}

@Composable
private fun Group(count: Int, row: @Composable (Int, Shape) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        for (i in 0 until count) row(i, segmentShape(i, count))
    }
}

@Composable
private fun RowShell(shape: Shape, onClick: (() -> Unit)?, content: @Composable RowScope.() -> Unit) {
    Surface(
        shape = shape,
        color = MaterialTheme.colorScheme.surfaceContainerLowest,
        modifier = Modifier.fillMaxWidth().let { if (onClick != null) it.clickable(onClick = onClick) else it },
    ) {
        Row(Modifier.heightIn(min = 64.dp).padding(horizontal = 20.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            content()
        }
    }
}

@Composable
private fun Texts(title: String, body: String?, modifier: Modifier = Modifier) {
    Column(modifier) {
        Text(title, style = MaterialTheme.typography.bodyLarge)
        if (body != null) Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun SwitchRow(title: String, body: String, on: Boolean, shape: Shape, set: (Boolean) -> Unit) =
    RowShell(shape, { set(!on) }) {
        Texts(title, body, Modifier.weight(1f))
        Switch(checked = on, onCheckedChange = set)
    }

@Composable
private fun ActionRow(title: String, body: String?, shape: Shape, onClick: () -> Unit) =
    RowShell(shape, onClick) { Texts(title, body) }

@Composable
private fun InfoRow(title: String, body: String, shape: Shape) = RowShell(shape, null) { Texts(title, body) }

@Composable
private fun <T> ChoiceRow(title: String, value: String, shape: Shape, options: List<Pair<String, T>>, pick: (T) -> Unit) {
    var open by remember { mutableStateOf(false) }
    RowShell(shape, { open = true }) { Texts(title, value) }
    if (open) {
        AlertDialog(
            onDismissRequest = { open = false },
            title = { Text(title) },
            text = {
                Column {
                    options.forEach { (label, v) ->
                        TextButton(onClick = { pick(v); open = false }, modifier = Modifier.fillMaxWidth()) { Text(label) }
                    }
                }
            },
            confirmButton = {},
        )
    }
}
