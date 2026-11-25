package dev.passwordvault.app.ui.cloud

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import dev.passwordvault.app.data.VaultRepository
import kotlinx.coroutines.launch

/**
 * Join cloud sync with the one-time link a computer shows (its Sync page,
 * Add a Device, or `vault cloud link`): paste it or scan its QR code. With no
 * vault here yet the vault is downloaded and then opens with the master
 * password; with a vault open, the two are merged.
 */
@Composable
fun CloudJoinDialog(vault: VaultRepository, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val open = vault.isUnlocked
    var link by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun join() {
        val l = link.trim()
        if (l.isEmpty() || busy) return
        busy = true
        error = null
        scope.launch {
            runCatching { if (open) vault.addCloud(l) else vault.joinCloud(l) }
                .onSuccess { onClose() }
                .onFailure { error = it.message ?: "Joining did not work." }
            busy = false
        }
    }

    AlertDialog(
        // Not closed halfway: the server may already know this phone.
        onDismissRequest = { if (!busy) onClose() },
        title = { Text("Cloud sync") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("On your computer, open Secret Vault's Sync page and choose Add a Device (or run vault cloud link). Scan the QR code it shows, or paste the link. A link works once, for 10 minutes.")
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = link,
                        onValueChange = { link = it },
                        label = { Text("Join link") },
                        maxLines = 4,
                        enabled = !busy,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
                        modifier = Modifier.weight(1f),
                    )
                    IconButton(enabled = !busy, onClick = {
                        val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
                        GmsBarcodeScanning.getClient(context, options).startScan()
                            .addOnSuccessListener { code -> code.rawValue?.let { link = it; join() } }
                            .addOnFailureListener { error = "The QR code scanner is not available: ${it.message}" }
                    }) { Icon(Icons.Outlined.QrCodeScanner, contentDescription = "Scan QR code") }
                }
                if (!open) {
                    Text(
                        "The vault is then downloaded to this phone. Open it with your master password.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            if (busy) {
                CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp)
            } else {
                TextButton(enabled = link.isNotBlank(), onClick = ::join) { Text(if (open) "Turn on cloud sync" else "Join") }
            }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onClose) { Text("Cancel") } },
    )
}
