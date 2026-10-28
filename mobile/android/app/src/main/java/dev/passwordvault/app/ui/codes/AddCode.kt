package dev.passwordvault.app.ui.codes

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowDropDown
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import dev.passwordvault.app.data.VaultRepository
import dev.passwordvault.app.ui.items.groupCode
import dev.passwordvault.app.ui.theme.Mono
import kotlinx.coroutines.launch
import uniffi.vault_mobile.ItemSummary
import uniffi.vault_mobile.Kind
import uniffi.vault_mobile.codeLabel
import uniffi.vault_mobile.previewTotp

/**
 * Adds a one-time code straight from the Codes screen: scan the site's QR
 * code or paste its setup key, then keep it on a new login or an existing one.
 */
@Composable
fun AddCodeDialog(vault: VaultRepository, items: List<ItemSummary>, onDone: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var input by remember { mutableStateOf("") }
    var title by remember { mutableStateOf("") }
    var account by remember { mutableStateOf("") }
    var target by remember { mutableStateOf<ItemSummary?>(null) }
    var picking by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    // Logins and notes that don't have a code yet.
    val candidates = remember(items) {
        items.filter { (it.kind == Kind.LOGIN || it.kind == Kind.NOTE) && !it.hasTotp && !it.hasKey }
            .sortedBy { it.title.lowercase() }
    }
    val preview = remember(input) {
        if (input.isBlank()) null else runCatching { previewTotp(input, (System.currentTimeMillis() / 1000).toULong()) }.getOrNull()
    }

    fun take(text: String) {
        input = text
        // An otpauth:// link names the site and account; pick the matching
        // login when there is exactly one.
        val label = codeLabel(text) ?: return
        if (title.isBlank()) title = label.issuer
        if (account.isBlank()) account = label.account
        val name = label.issuer.lowercase()
        val same = candidates.filter { name.isNotEmpty() && (it.title.lowercase().contains(name) || it.host?.contains(name) == true) }
        if (target == null && same.size == 1) target = same[0]
    }

    AlertDialog(
        onDismissRequest = onDone,
        title = { Text("Add a one-time code") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "When a site turns on two-factor sign-in it shows a QR code for an authenticator app. Scan it, or paste the setup key the site shows under \"Can't scan?\".",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = input,
                        onValueChange = ::take,
                        label = { Text("Setup key or otpauth:// link") },
                        textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = Mono),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                        modifier = Modifier.weight(1f),
                    )
                    IconButton(onClick = {
                        val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
                        GmsBarcodeScanning.getClient(context, options).startScan()
                            .addOnSuccessListener { code -> code.rawValue?.let(::take) }
                            .addOnFailureListener { error = "The QR code scanner is not available: ${it.message}" }
                    }) { Icon(Icons.Outlined.QrCodeScanner, contentDescription = "Scan QR code") }
                }
                when {
                    preview != null -> Text("Current code: ${groupCode(preview.code)}", color = MaterialTheme.colorScheme.primary)
                    input.isNotBlank() -> Text("This isn't a key the vault understands yet.", color = MaterialTheme.colorScheme.error)
                }
                Text("Save to", style = MaterialTheme.typography.labelLarge)
                Box {
                    OutlinedButton(onClick = { picking = true }, modifier = Modifier.fillMaxWidth()) {
                        Text(target?.title ?: "A new login", modifier = Modifier.weight(1f), maxLines = 2, overflow = TextOverflow.Ellipsis)
                        Icon(Icons.Outlined.ArrowDropDown, contentDescription = null)
                    }
                    DropdownMenu(expanded = picking, onDismissRequest = { picking = false }) {
                        DropdownMenuItem(text = { Text("A new login") }, onClick = { target = null; picking = false })
                        candidates.forEach { item ->
                            DropdownMenuItem(text = { Text(item.title) }, onClick = { target = item; picking = false })
                        }
                    }
                }
                if (target == null) {
                    OutlinedTextField(title, { title = it }, label = { Text("Name, e.g. Example Mail") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(
                        account, { account = it },
                        label = { Text("Account, e.g. alex@example.com") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                Text(
                    "Keep the code on the login for the same site, so autofill can offer the code right after the password.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(enabled = preview != null, onClick = {
                scope.launch {
                    runCatching { vault.addCode(input, title, account, target?.id) }
                        .onSuccess { onDone() }
                        .onFailure { error = it.message }
                }
            }) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDone) { Text("Cancel") } },
    )
}
