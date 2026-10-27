package dev.passwordvault.app.ui.generator

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.passwordvault.app.data.VaultRepository
import dev.passwordvault.app.ui.items.rememberCopier
import dev.passwordvault.app.ui.theme.Mono
import uniffi.vault_mobile.GeneratorOptions
import uniffi.vault_mobile.generatePassword

@Composable
fun GeneratorScreen(vault: VaultRepository) {
    val copy = rememberCopier(vault)
    var length by rememberSaveable { mutableFloatStateOf(20f) }
    var upper by rememberSaveable { mutableStateOf(true) }
    var digits by rememberSaveable { mutableStateOf(true) }
    var symbols by rememberSaveable { mutableStateOf(true) }
    var ambiguous by rememberSaveable { mutableStateOf(true) }
    var password by rememberSaveable { mutableStateOf("") }

    fun regenerate() {
        password = runCatching {
            generatePassword(GeneratorOptions(length.toUInt(), true, upper, digits, symbols, ambiguous))
        }.getOrDefault("")
    }
    LaunchedEffect(length.toInt(), upper, digits, symbols, ambiguous) { regenerate() }

    Column(
        Modifier.fillMaxSize().statusBarsPadding().verticalScroll(rememberScrollState()).padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(Modifier.widthIn(max = 560.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("Password generator", style = MaterialTheme.typography.headlineMedium)
            Surface(shape = RoundedCornerShape(28.dp), color = MaterialTheme.colorScheme.primaryContainer, modifier = Modifier.fillMaxWidth()) {
                Text(
                    password,
                    fontFamily = Mono,
                    fontSize = 24.sp,
                    lineHeight = 34.sp,
                    textAlign = TextAlign.Center,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                    modifier = Modifier.padding(28.dp),
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(onClick = { copy("Password", password, true) }, modifier = Modifier.weight(1f).height(56.dp)) { Text("Copy") }
                FilledTonalButton(onClick = ::regenerate, modifier = Modifier.weight(1f).height(56.dp)) { Text("New password") }
            }
            Text("Length: ${length.toInt()}", style = MaterialTheme.typography.titleMedium)
            Slider(value = length, onValueChange = { length = it }, valueRange = 8f..64f, steps = 55)
            Option("A to Z", upper) { upper = it }
            Option("0 to 9", digits) { digits = it }
            Option("Symbols (!@#…)", symbols) { symbols = it }
            Option("Leave out look-alikes (0 O 1 l I)", ambiguous) { ambiguous = it }
        }
    }
}

@Composable
private fun Option(label: String, on: Boolean, set: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Switch(checked = on, onCheckedChange = set)
    }
}
