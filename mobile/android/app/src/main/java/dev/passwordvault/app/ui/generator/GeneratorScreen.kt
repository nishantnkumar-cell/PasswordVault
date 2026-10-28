package dev.passwordvault.app.ui.generator

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.passwordvault.app.data.Settings
import dev.passwordvault.app.data.VaultRepository
import dev.passwordvault.app.ui.items.rememberCopier
import dev.passwordvault.app.ui.theme.Mono
import kotlin.math.roundToInt
import uniffi.vault_mobile.GeneratorOptions
import uniffi.vault_mobile.PasswordStyle
import uniffi.vault_mobile.generateStyled
import uniffi.vault_mobile.passwordStrength

private val styles = listOf("random" to "Random", "words" to "3 words", "apple" to "Apple style")
private val separators = listOf("" to "Nothing", "-" to "-", "." to ".", " " to "Space")

/** The style the Generator screen is set to, which the editor's Generate button uses too. */
fun savedStyle(s: Settings): PasswordStyle = when (s.generatorStyle) {
    "words" -> PasswordStyle.Words(s.generatorWords.toUInt(), s.generatorSeparator, s.generatorCapitalize, s.generatorNumberAndSymbol)
    "apple" -> PasswordStyle.Apple
    else -> PasswordStyle.Random(GeneratorOptions(20u, true, true, true, true, true))
}

/**
 * Makes passwords with the same generator as the desktop app: random
 * characters, three random words (the UK NCSC's advice) or Apple style.
 */
@Composable
fun GeneratorScreen(vault: VaultRepository) {
    val copy = rememberCopier(vault)
    val settings = vault.settings
    var kind by rememberSaveable { mutableStateOf(settings.generatorStyle) }
    var length by rememberSaveable { mutableFloatStateOf(20f) }
    var upper by rememberSaveable { mutableStateOf(true) }
    var digits by rememberSaveable { mutableStateOf(true) }
    var symbols by rememberSaveable { mutableStateOf(true) }
    var ambiguous by rememberSaveable { mutableStateOf(true) }
    var words by rememberSaveable { mutableIntStateOf(settings.generatorWords) }
    var separator by rememberSaveable { mutableStateOf(settings.generatorSeparator) }
    var capitalize by rememberSaveable { mutableStateOf(settings.generatorCapitalize) }
    var extra by rememberSaveable { mutableStateOf(settings.generatorNumberAndSymbol) }
    var password by rememberSaveable { mutableStateOf("") }

    val style = when (kind) {
        "words" -> PasswordStyle.Words(words.toUInt(), separator, capitalize, extra)
        "apple" -> PasswordStyle.Apple
        else -> PasswordStyle.Random(GeneratorOptions(length.toUInt(), true, upper, digits, symbols, ambiguous))
    }
    fun regenerate() {
        password = runCatching { generateStyled(style) }.getOrDefault("")
    }
    LaunchedEffect(style) {
        settings.generatorStyle = kind
        settings.generatorWords = words
        settings.generatorSeparator = separator
        settings.generatorCapitalize = capitalize
        settings.generatorNumberAndSymbol = extra
        regenerate()
    }

    Column(
        Modifier.fillMaxSize().statusBarsPadding().verticalScroll(rememberScrollState()).padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(Modifier.widthIn(max = 560.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("Password generator", style = MaterialTheme.typography.headlineMedium)
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                styles.forEachIndexed { i, (key, label) ->
                    SegmentedButton(
                        selected = kind == key,
                        onClick = { kind = key },
                        shape = SegmentedButtonDefaults.itemShape(i, styles.size),
                    ) { Text(label, maxLines = 1, softWrap = false) }
                }
            }
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
                Button(onClick = { copy("Password", password, true) }, modifier = Modifier.weight(1f).heightIn(min = 56.dp)) { Text("Copy") }
                FilledTonalButton(onClick = ::regenerate, modifier = Modifier.weight(1f).heightIn(min = 56.dp)) {
                    Text("New password", textAlign = TextAlign.Center)
                }
            }
            Text(about(kind, passwordStrength(style).roundToInt()), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            when (kind) {
                "words" -> {
                    Text("Words: $words", style = MaterialTheme.typography.titleMedium)
                    Slider(value = words.toFloat(), onValueChange = { words = it.roundToInt() }, valueRange = 3f..10f, steps = 6)
                    Text("Between words", style = MaterialTheme.typography.titleMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        separators.forEach { (sep, label) ->
                            FilterChip(selected = separator == sep, onClick = { separator = sep }, label = { Text(label) })
                        }
                    }
                    Option("Capital letter at the start of each word", capitalize) { capitalize = it }
                    Option("Add a number and a symbol at the end, for sites that demand them", extra) { extra = it }
                }
                "apple" -> {}
                else -> {
                    Text("Length: ${length.toInt()}", style = MaterialTheme.typography.titleMedium)
                    Slider(value = length, onValueChange = { length = it }, valueRange = 8f..64f, steps = 55)
                    Option("A to Z", upper) { upper = it }
                    Option("0 to 9", digits) { digits = it }
                    Option("Symbols (!@#…)", symbols) { symbols = it }
                    Option("Leave out look-alikes (0 O 1 l I)", ambiguous) { ambiguous = it }
                }
            }
        }
    }
}

private fun about(kind: String, bits: Int) = when (kind) {
    "words" -> "Three random words, as the UK's National Cyber Security Centre recommends: easy to remember and type, like CupFishBiscuit. About $bits bits; use four or more words for anything that matters most."
    "apple" -> "Like the passwords Apple devices suggest: three groups of six letters with one capital and one digit, easy to type on a phone keyboard. About $bits bits."
    else -> "Random characters: about $bits bits. Strongest for its length; best when autofill types it for you."
}

@Composable
private fun Option(label: String, on: Boolean, set: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f).padding(end = 12.dp))
        Switch(checked = on, onCheckedChange = set)
    }
}
