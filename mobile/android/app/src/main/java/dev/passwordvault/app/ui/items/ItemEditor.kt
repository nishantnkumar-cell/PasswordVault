package dev.passwordvault.app.ui.items

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
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
import dev.passwordvault.app.data.Settings
import dev.passwordvault.app.data.VaultRepository
import dev.passwordvault.app.ui.components.SectionLabel
import dev.passwordvault.app.ui.generator.savedStyle
import dev.passwordvault.app.ui.unlock.SecretField
import kotlinx.coroutines.launch
import uniffi.vault_mobile.CardRecord
import uniffi.vault_mobile.FieldRecord
import uniffi.vault_mobile.IdentityRecord
import uniffi.vault_mobile.ItemDetail
import uniffi.vault_mobile.ItemEdit
import uniffi.vault_mobile.Kind
import uniffi.vault_mobile.TotpEdit
import uniffi.vault_mobile.UrlRecord
import uniffi.vault_mobile.generateStyled

private class UrlDraft(url: String, sub: Boolean) {
    var url by mutableStateOf(url)
    var sub by mutableStateOf(sub)
}

private class FieldDraft(name: String, value: String, hidden: Boolean) {
    var name by mutableStateOf(name)
    var value by mutableStateOf(value)
    var hidden by mutableStateOf(hidden)
}

/**
 * A new password for the "Generate" button, in the style the Generator
 * screen is set to (20 random characters of every kind until it's changed).
 */
fun strongPassword(settings: Settings): String = generateStyled(savedStyle(settings))

/** Create or edit an item. [onDone] gets the saved ID, or null on cancel. */
@Composable
fun ItemEditor(
    vault: VaultRepository,
    id: String?,
    newKind: Kind,
    showBack: Boolean,
    existing: ItemDetail? = null,
    onDone: (String?) -> Unit,
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val kind = existing?.kind ?: newKind
    var title by remember { mutableStateOf(existing?.title ?: "") }
    var username by remember { mutableStateOf(existing?.username ?: "") }
    var password by remember { mutableStateOf(existing?.password ?: if (kind == Kind.LOGIN) strongPassword(vault.settings) else "") }
    val urls = remember {
        mutableStateListOf<UrlDraft>().apply {
            existing?.urls?.forEach { add(UrlDraft(it.url, it.matchSubdomains)) }
            if (isEmpty() && kind == Kind.LOGIN) add(UrlDraft("", false))
        }
    }
    var totpInput by remember { mutableStateOf("") }
    var removeTotp by remember { mutableStateOf(false) }
    val card = existing?.card
    var holder by remember { mutableStateOf(card?.holder ?: "") }
    var number by remember { mutableStateOf(card?.number ?: "") }
    var expiry by remember {
        mutableStateOf(card?.takeIf { it.expMonth > 0u }?.let { "%02d/%02d".format(it.expMonth.toInt(), it.expYear.toInt() % 100) } ?: "")
    }
    var cvv by remember { mutableStateOf(card?.cvv ?: "") }
    var pin by remember { mutableStateOf(card?.pin ?: "") }
    val ident = existing?.identity ?: IdentityRecord("", "", "", "", "", "", "", "", "", "", "", "", "", "")
    var person by remember { mutableStateOf(ident) }
    val fields = remember {
        mutableStateListOf<FieldDraft>().apply { existing?.fields?.forEach { add(FieldDraft(it.name, it.value, it.hidden)) } }
    }
    var notes by remember { mutableStateOf(existing?.notes ?: "") }
    var error by remember { mutableStateOf<String?>(null) }
    var saving by remember { mutableStateOf(false) }

    fun save() {
        val (month, year) = parseExpiry(expiry)
        val edit = ItemEdit(
            kind = kind,
            title = title,
            username = username,
            password = password,
            urls = urls.map { UrlRecord(it.url, it.sub, false) },
            totp = when {
                totpInput.isNotBlank() -> TotpEdit.Set(totpInput)
                removeTotp -> TotpEdit.Remove
                else -> TotpEdit.Keep
            },
            card = if (kind == Kind.CARD) CardRecord(holder, number, month, year, cvv, pin, null, false) else null,
            identity = if (kind == Kind.IDENTITY) person else null,
            fields = fields.map { FieldRecord(it.name, it.value, it.hidden, false) },
            notes = notes,
        )
        saving = true
        scope.launch {
            runCatching { vault.save(id, edit) }
                .onSuccess { onDone(it) }
                .onFailure { error = it.message }
            saving = false
        }
    }

    Column(
        Modifier.fillMaxSize().statusBarsPadding().imePadding().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(top = 4.dp)) {
            if (showBack) IconButton(onClick = { onDone(null) }) { Icon(Icons.Outlined.Close, contentDescription = "Cancel") }
            Text(
                if (existing == null) "New ${kindLabel(kind).lowercase()}" else "Edit ${kindLabel(kind).lowercase()}",
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.weight(1f).padding(start = 4.dp),
            )
            Button(onClick = ::save, enabled = !saving && title.isNotBlank()) { Text("Save") }
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }

        Field("Title", title, { title = it })
        when (kind) {
            Kind.LOGIN -> {
                Field("Username or email", username, { username = it }, KeyboardType.Email)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SecretField(password, { password = it }, "Password", Modifier.weight(1f))
                    IconButton(onClick = { password = strongPassword(vault.settings) }) {
                        Icon(Icons.Outlined.Refresh, contentDescription = "Generate a new password")
                    }
                }
                SectionLabel("Websites")
                urls.forEachIndexed { i, u ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Field("Website", u.url, { u.url = it }, KeyboardType.Uri, Modifier.weight(1f))
                        IconButton(onClick = { urls.removeAt(i) }) { Icon(Icons.Outlined.Delete, contentDescription = "Remove website") }
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = u.sub, onCheckedChange = { u.sub = it })
                        Text("Also fill on its subdomains", style = MaterialTheme.typography.bodyMedium)
                    }
                }
                TextButton(onClick = { urls.add(UrlDraft("", false)) }) {
                    Icon(Icons.Outlined.Add, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text("Add website")
                }
                SectionLabel("One-time code")
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Field(
                        if (existing?.hasTotp == true && !removeTotp) "Replace setup key (leave empty to keep)" else "Setup key or otpauth:// link",
                        totpInput, { totpInput = it }, KeyboardType.Ascii, Modifier.weight(1f),
                    )
                    IconButton(onClick = {
                        val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
                        GmsBarcodeScanning.getClient(context, options).startScan()
                            .addOnSuccessListener { code -> code.rawValue?.let { totpInput = it } }
                            .addOnFailureListener { error = "The QR code scanner is not available: ${it.message}" }
                    }) { Icon(Icons.Outlined.QrCodeScanner, contentDescription = "Scan QR code") }
                }
                if (existing?.hasTotp == true) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = removeTotp, onCheckedChange = { removeTotp = it })
                        Text("Remove the one-time code", style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
            Kind.CARD -> {
                Field("Name on card", holder, { holder = it })
                Field("Card number", number, { number = it }, KeyboardType.Number)
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Field("Expires (MM/YY)", expiry, { expiry = it }, KeyboardType.Number, Modifier.weight(1f))
                    Field("Security code", cvv, { cvv = it }, KeyboardType.NumberPassword, Modifier.weight(1f))
                }
                Field("PIN", pin, { pin = it }, KeyboardType.NumberPassword)
            }
            Kind.IDENTITY -> {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Field("First name", person.givenName, { person = person.copy(givenName = it) }, modifier = Modifier.weight(1f))
                    Field("Last name", person.familyName, { person = person.copy(familyName = it) }, modifier = Modifier.weight(1f))
                }
                Field("Company", person.company, { person = person.copy(company = it) })
                Field("Email", person.email, { person = person.copy(email = it) }, KeyboardType.Email)
                Field("Phone", person.phone, { person = person.copy(phone = it) }, KeyboardType.Phone)
                Field("Address", person.address1, { person = person.copy(address1 = it) })
                Field("Address line 2", person.address2, { person = person.copy(address2 = it) })
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Field("City", person.city, { person = person.copy(city = it) }, modifier = Modifier.weight(1f))
                    Field("Postcode", person.postcode, { person = person.copy(postcode = it) }, modifier = Modifier.weight(1f))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Field("State or region", person.region, { person = person.copy(region = it) }, modifier = Modifier.weight(1f))
                    Field("Country", person.country, { person = person.copy(country = it) }, modifier = Modifier.weight(1f))
                }
            }
            Kind.NOTE -> {}
        }

        SectionLabel("More fields")
        fields.forEachIndexed { i, f ->
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Field("Label", f.name, { f.name = it }, modifier = Modifier.weight(0.8f))
                Field("Value", f.value, { f.value = it }, modifier = Modifier.weight(1.2f))
                IconButton(onClick = { fields.removeAt(i) }) { Icon(Icons.Outlined.Delete, contentDescription = "Remove field") }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = f.hidden, onCheckedChange = { f.hidden = it })
                Text("Hide the value", style = MaterialTheme.typography.bodyMedium)
            }
        }
        TextButton(onClick = { fields.add(FieldDraft("", "", false)) }) {
            Icon(Icons.Outlined.Add, contentDescription = null)
            Spacer(Modifier.width(6.dp))
            Text("Add field")
        }
        OutlinedTextField(
            value = notes,
            onValueChange = { notes = it },
            label = { Text("Notes") },
            minLines = if (kind == Kind.NOTE) 8 else 3,
            shape = MaterialTheme.shapes.medium,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.size(48.dp))
    }
}

@Composable
private fun Field(
    label: String,
    value: String,
    onChange: (String) -> Unit,
    keyboard: KeyboardType = KeyboardType.Text,
    modifier: Modifier = Modifier.fillMaxWidth(),
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = keyboard),
        shape = MaterialTheme.shapes.medium,
        modifier = modifier,
    )
}

/** "08/29", "8/2029" or "0829" to (8, 2029); (0, 0) when empty or unreadable. */
fun parseExpiry(s: String): Pair<UByte, UShort> {
    val digits = s.filter { it.isDigit() || it == '/' }
    val parts = if ('/' in digits) digits.split('/') else listOf(digits.take(2), digits.drop(2))
    val m = parts.getOrNull(0)?.toIntOrNull() ?: return 0.toUByte() to 0.toUShort()
    var y = parts.getOrNull(1)?.toIntOrNull() ?: return 0.toUByte() to 0.toUShort()
    if (m !in 1..12) return 0.toUByte() to 0.toUShort()
    if (y < 100) y += 2000
    return m.toUByte() to y.toUShort()
}
