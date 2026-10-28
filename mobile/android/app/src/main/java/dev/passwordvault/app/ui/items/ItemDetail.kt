package dev.passwordvault.app.ui.items

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.OpenInNew
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.passwordvault.app.data.VaultRepository
import dev.passwordvault.app.ui.components.FieldRow
import dev.passwordvault.app.ui.components.LetterTile
import dev.passwordvault.app.ui.components.SecureClipboard
import dev.passwordvault.app.ui.components.SectionLabel
import dev.passwordvault.app.ui.components.TotpRing
import dev.passwordvault.app.ui.components.segmentShape
import dev.passwordvault.app.ui.theme.CodeStyle
import dev.passwordvault.app.ui.theme.LocalVaultColors
import dev.passwordvault.app.ui.theme.Mono
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import uniffi.vault_mobile.ItemDetail
import uniffi.vault_mobile.Kind
import uniffi.vault_mobile.TotpCode

/** Copy with the user's clear-after setting, and say so. */
@Composable
fun rememberCopier(vault: VaultRepository): (label: String, value: String, sensitive: Boolean) -> Unit {
    val context = LocalContext.current
    return remember(vault) {
        { label, value, sensitive ->
            SecureClipboard.copy(context, label, value, sensitive, vault.settings.clipboardSeconds)
            android.widget.Toast.makeText(
                context,
                if (sensitive) "$label copied. Clears in ${vault.settings.clipboardSeconds} s." else "$label copied.",
                android.widget.Toast.LENGTH_SHORT,
            ).show()
        }
    }
}

/** The current code for an item, ticking every second. */
@Composable
fun rememberTotp(vault: VaultRepository, id: String, enabled: Boolean): TotpCode? {
    var code by remember(id) { mutableStateOf<TotpCode?>(null) }
    LaunchedEffect(id, enabled) {
        while (enabled) {
            code = runCatching { vault.totp(id) }.getOrNull()
            delay(1000)
        }
    }
    return code
}

fun groupCode(code: String) = if (code.length == 6) code.take(3) + " " + code.drop(3) else code

@Composable
fun ItemDetailPane(
    vault: VaultRepository,
    id: String,
    showBack: Boolean,
    onBack: () -> Unit,
    onDeleted: () -> Unit,
) {
    val revision by vault.revision.collectAsStateWithLifecycle()
    val item = remember(id, revision) { vault.item(id) }
    var editing by remember(id) { mutableStateOf(false) }
    if (item == null) {
        LaunchedEffect(id) { onDeleted() }
        return
    }
    if (editing) {
        ItemEditor(vault, id, item.kind, showBack = true, existing = item, onDone = { editing = false })
        return
    }
    val copy = rememberCopier(vault)
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var menu by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().statusBarsPadding().verticalScroll(rememberScrollState()).padding(horizontal = 12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(top = 4.dp)) {
            if (showBack) {
                IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back") }
            }
            Spacer(Modifier.weight(1f))
            OutlinedButton(onClick = { editing = true }) { Text("Edit") }
            Box {
                IconButton(onClick = { menu = true }) { Icon(Icons.Outlined.MoreVert, contentDescription = "More options") }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(text = { Text("Delete") }, onClick = { menu = false; confirmDelete = true })
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(start = 12.dp, top = 12.dp, bottom = 20.dp)) {
            LetterTile(item.title, size = 64.dp, shape = RoundedCornerShape(22.dp))
            Spacer(Modifier.width(16.dp))
            Column {
                Text(item.title, style = MaterialTheme.typography.headlineMedium)
                val edited = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(item.modified.toLong() * 1000))
                Text("${kindLabel(item.kind)} · edited $edited", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        if (item.hasTotp) {
            val code = rememberTotp(vault, id, true)
            if (code != null) TotpCard(code) { copy("One-time code", code.code, true) }
            Spacer(Modifier.size(12.dp))
        }

        when (item.kind) {
            Kind.LOGIN -> LoginFields(item, copy, context)
            Kind.CARD -> CardFields(item, copy)
            Kind.IDENTITY -> IdentityFields(item, copy)
            Kind.NOTE -> {}
        }

        item.key?.let { k ->
            SectionLabel("Key")
            Surface(shape = RoundedCornerShape(22.dp), color = MaterialTheme.colorScheme.surfaceContainerLowest, modifier = Modifier.fillMaxWidth()) {
                Text(
                    "$k. Your computer's vault daemon uses it for SSH and Git signing; the phone app shows it but does not use it.",
                    modifier = Modifier.padding(20.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        if (item.fields.isNotEmpty()) {
            SectionLabel("More fields")
            Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                item.fields.forEachIndexed { i, f ->
                    var shown by remember { mutableStateOf(!f.hidden) }
                    FieldRow(f.name, segmentShape(i, item.fields.size), actions = {
                        if (f.hidden) {
                            ToggleShow(shown) { shown = !shown }
                        }
                        CopyButton("Copy ${f.name}") { copy(f.name, f.value, f.hidden) }
                    }) {
                        Text(if (shown) f.value else "••••••••", style = MaterialTheme.typography.bodyLarge)
                    }
                }
            }
        }

        if (item.notes.isNotBlank()) {
            SectionLabel("Notes")
            Surface(shape = RoundedCornerShape(22.dp), color = MaterialTheme.colorScheme.surfaceContainerLowest, modifier = Modifier.fillMaxWidth()) {
                Text(item.notes, modifier = Modifier.padding(20.dp), style = MaterialTheme.typography.bodyLarge)
            }
        }
        Spacer(Modifier.size(48.dp))
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete ${item.title}?") },
            text = { Text("It is deleted on every device that syncs this vault.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    scope.launch { vault.delete(id); onDeleted() }
                }) { Text("Delete", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } },
        )
    }
}

@Composable
fun TotpCard(code: TotpCode, onCopy: () -> Unit) {
    Surface(shape = RoundedCornerShape(28.dp), color = MaterialTheme.colorScheme.primaryContainer, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(horizontal = 20.dp, vertical = 18.dp), verticalAlignment = Alignment.CenterVertically) {
            TotpRing(code.remaining.toInt(), code.period.toInt(), size = 54.dp, label = true)
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text("One-time code", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onPrimaryContainer)
                Text(groupCode(code.code), style = CodeStyle, color = MaterialTheme.colorScheme.onPrimaryContainer)
            }
            FilledIconButton(
                onClick = onCopy,
                modifier = Modifier.size(56.dp),
                shape = RoundedCornerShape(18.dp),
            ) { Icon(Icons.Outlined.ContentCopy, contentDescription = "Copy one-time code") }
        }
    }
}

@Composable
fun CopyButton(description: String, onClick: () -> Unit) {
    FilledTonalIconButton(
        onClick = onClick,
        colors = IconButtonDefaults.filledTonalIconButtonColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) { Icon(Icons.Outlined.ContentCopy, contentDescription = description) }
}

@Composable
fun ToggleShow(shown: Boolean, onClick: () -> Unit) {
    FilledTonalIconButton(
        onClick = onClick,
        colors = IconButtonDefaults.filledTonalIconButtonColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Icon(
            if (shown) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
            contentDescription = if (shown) "Hide" else "Show",
        )
    }
}

@Composable
private fun LoginFields(item: ItemDetail, copy: (String, String, Boolean) -> Unit, context: android.content.Context) {
    var shown by remember(item.id) { mutableStateOf(false) }
    val rows = buildList {
        if (item.username.isNotEmpty()) add("user")
        if (item.password.isNotEmpty()) add("pass")
        item.urls.forEachIndexed { i, _ -> add("url$i") }
    }
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        rows.forEachIndexed { i, r ->
            val shape = segmentShape(i, rows.size)
            when {
                r == "user" -> FieldRow("Username", shape, actions = {
                    CopyButton("Copy username") { copy("Username", item.username, false) }
                }) { Text(item.username, style = MaterialTheme.typography.bodyLarge) }
                r == "pass" -> FieldRow("Password", shape, actions = {
                    ToggleShow(shown) { shown = !shown }
                    CopyButton("Copy password") { copy("Password", item.password, true) }
                }) {
                    Text(
                        if (shown) item.password else "••••••••••••",
                        style = MaterialTheme.typography.bodyLarge.copy(fontFamily = if (shown) Mono else null),
                    )
                }
                else -> {
                    val u = item.urls[r.removePrefix("url").toInt()]
                    FieldRow("Autofill is bound to", shape, actions = {
                        IconButton(onClick = {
                            runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(u.url))) }
                        }) { Icon(Icons.Outlined.OpenInNew, contentDescription = "Open ${u.url}") }
                    }) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Outlined.VerifiedUser,
                                contentDescription = null,
                                tint = LocalVaultColors.current.ok,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(Modifier.width(6.dp))
                            Text(u.url, fontFamily = Mono, style = MaterialTheme.typography.bodyMedium)
                        }
                        Text(
                            if (u.matchSubdomains) "this site and its subdomains" else "this site only",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun CardFields(item: ItemDetail, copy: (String, String, Boolean) -> Unit) {
    val c = item.card ?: return
    var shown by remember(item.id) { mutableStateOf(false) }
    CardArt(c.holder, c.number, c.brand, c.expMonth.toInt(), c.expYear.toInt(), shown)
    Spacer(Modifier.size(12.dp))
    val rows = listOfNotNull(
        "number".takeIf { c.number.isNotEmpty() },
        "cvv".takeIf { c.cvv.isNotEmpty() },
        "pin".takeIf { c.pin.isNotEmpty() },
    )
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        rows.forEachIndexed { i, r ->
            val shape = segmentShape(i, rows.size)
            when (r) {
                "number" -> FieldRow("Card number", shape, actions = {
                    ToggleShow(shown) { shown = !shown }
                    CopyButton("Copy card number") { copy("Card number", c.number, true) }
                }) { Text(if (shown) c.number.chunked(4).joinToString(" ") else "•••• ${c.number.takeLast(4)}", fontFamily = Mono) }
                "cvv" -> FieldRow("Security code", shape, actions = {
                    CopyButton("Copy security code") { copy("Security code", c.cvv, true) }
                }) { Text(if (shown) c.cvv else "•••", fontFamily = Mono) }
                else -> FieldRow("PIN", shape, actions = {
                    CopyButton("Copy PIN") { copy("PIN", c.pin, true) }
                }) { Text(if (shown) c.pin else "••••", fontFamily = Mono) }
            }
        }
    }
    if (!c.numberValid && c.number.isNotEmpty()) {
        Text(
            "This number fails the card checksum; check it for a typo.",
            color = LocalVaultColors.current.warn,
            modifier = Modifier.padding(12.dp),
        )
    }
}

@Composable
fun CardArt(holder: String, number: String, brand: String?, month: Int, year: Int, shown: Boolean) {
    val bg = Brush.linearGradient(listOf(Color(0xFF1D3FA8), Color(0xFF2C55D4), Color(0xFF5B7BE8)))
    Box(
        Modifier.widthIn(max = 420.dp).fillMaxWidth().aspectRatio(1.586f).clip(RoundedCornerShape(24.dp)).background(bg).padding(22.dp),
    ) {
        val white = Color.White
        Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.SpaceBetween) {
            Row(Modifier.fillMaxWidth()) {
                Text(holder, color = white, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                Text(brand?.uppercase() ?: "", color = white, style = MaterialTheme.typography.titleMedium)
            }
            Text(
                if (shown) number.chunked(4).joinToString(" ") else "•••• •••• •••• ${number.takeLast(4)}",
                color = white,
                fontFamily = Mono,
                style = MaterialTheme.typography.headlineSmall,
            )
            Text(
                if (month > 0 && year > 0) "Expires %02d/%02d".format(month, year % 100) else "",
                color = white,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
private fun IdentityFields(item: ItemDetail, copy: (String, String, Boolean) -> Unit) {
    val p = item.identity ?: return
    val name = listOf(p.honorific, p.givenName, p.middleName, p.familyName).filter { it.isNotBlank() }.joinToString(" ")
    val address = listOf(
        p.address1, p.address2, p.address3,
        listOf(p.city, p.region, p.postcode).filter { it.isNotBlank() }.joinToString(", "),
        p.country,
    ).filter { it.isNotBlank() }.joinToString("\n")
    val rows = listOf("Name" to name, "Company" to p.company, "Email" to p.email, "Phone" to p.phone, "Address" to address)
        .filter { it.second.isNotBlank() }
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        rows.forEachIndexed { i, (label, value) ->
            FieldRow(label, segmentShape(i, rows.size), actions = {
                CopyButton("Copy $label") { copy(label, value, false) }
            }) { Text(value, style = MaterialTheme.typography.bodyLarge) }
        }
    }
}
