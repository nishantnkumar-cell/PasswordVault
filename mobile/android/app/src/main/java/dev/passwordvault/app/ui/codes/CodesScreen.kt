package dev.passwordvault.app.ui.codes

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.adaptive.currentWindowAdaptiveInfo
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.passwordvault.app.data.VaultRepository
import dev.passwordvault.app.ui.components.LetterTile
import dev.passwordvault.app.ui.components.TotpRing
import dev.passwordvault.app.ui.items.groupCode
import dev.passwordvault.app.ui.items.rememberCopier
import dev.passwordvault.app.ui.theme.CodeStyle
import dev.passwordvault.app.ui.theme.Mono
import kotlinx.coroutines.delay
import uniffi.vault_mobile.ItemSummary
import uniffi.vault_mobile.TotpCode

/** Re-reads every code once a second while the screen is shown. */
@Composable
private fun rememberCodes(vault: VaultRepository, items: List<ItemSummary>): Map<String, TotpCode> {
    var tick by remember { mutableLongStateOf(0L) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(1000)
            tick++
        }
    }
    return remember(items, tick) {
        items.mapNotNull { s -> runCatching { vault.totp(s.id) }.getOrNull()?.let { s.id to it } }.toMap()
    }
}

/**
 * Every one-time code at a glance. Half-folded on a table, a foldable shows
 * the selected code large above the hinge and the buttons below it.
 */
@Composable
fun CodesScreen(vault: VaultRepository) {
    val all by vault.items.collectAsStateWithLifecycle()
    val items = remember(all) { all.filter { it.hasTotp } }
    val codes = rememberCodes(vault, items)
    val copy = rememberCopier(vault)
    var selected by rememberSaveable { mutableStateOf<String?>(null) }
    val posture = currentWindowAdaptiveInfo().windowPosture
    var adding by rememberSaveable { mutableStateOf(false) }
    if (adding) AddCodeDialog(vault, all) { adding = false }

    if (items.isEmpty()) {
        Box(Modifier.fillMaxSize().statusBarsPadding().padding(32.dp), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text(
                    "No one-time codes yet. Scan a site's QR code or paste its setup key to keep its two-factor codes here.",
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                Button(onClick = { adding = true }) {
                    Icon(Icons.Outlined.Add, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Add code")
                }
            }
        }
        return
    }

    val hinge = posture.hingeList.firstOrNull()
    if (posture.isTabletop && hinge != null) {
        val focus = items.firstOrNull { it.id == selected } ?: items.first()
        val code = codes[focus.id]
        val topHeight = with(LocalDensity.current) { hinge.bounds.top.toDp() }
        Column(Modifier.fillMaxSize()) {
            Surface(color = MaterialTheme.colorScheme.primaryContainer, modifier = Modifier.fillMaxWidth().height(topHeight)) {
                Column(
                    Modifier.fillMaxSize().statusBarsPadding(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Text(
                        "${focus.title} · ${focus.subtitle}",
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 24.dp),
                    )
                    Text(
                        code?.let { groupCode(it.code) } ?: "",
                        fontFamily = Mono,
                        fontSize = 88.sp,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                    if (code != null) {
                        LinearProgressIndicator(
                            progress = { code.remaining.toFloat() / code.period.toFloat() },
                            modifier = Modifier.width(420.dp).height(10.dp),
                        )
                        Spacer(Modifier.height(10.dp))
                        Text("${code.remaining} seconds left", color = MaterialTheme.colorScheme.onPrimaryContainer)
                    }
                }
            }
            Spacer(Modifier.height(with(LocalDensity.current) { hinge.bounds.height.toDp() } + 16.dp))
            Row(Modifier.padding(horizontal = 32.dp), horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                Button(
                    onClick = { code?.let { copy("One-time code", it.code, true) } },
                    modifier = Modifier.weight(1f).height(88.dp),
                    shape = RoundedCornerShape(28.dp),
                ) { Text("Copy code", style = MaterialTheme.typography.titleMedium) }
            }
            CodeGrid(items, codes, selectedId = focus.id, onPick = { selected = it.id })
        }
        return
    }

    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        Row(
            Modifier.fillMaxWidth().padding(start = 24.dp, end = 16.dp, top = 16.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("One-time codes", style = MaterialTheme.typography.headlineMedium, modifier = Modifier.weight(1f))
            FilledTonalButton(onClick = { adding = true }) {
                Icon(Icons.Outlined.Add, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Add code")
            }
        }
        CodeGrid(items, codes, selectedId = null, onPick = { s -> codes[s.id]?.let { copy("One-time code", it.code, true) } })
    }
}

@Composable
private fun CodeGrid(
    items: List<ItemSummary>,
    codes: Map<String, TotpCode>,
    selectedId: String?,
    onPick: (ItemSummary) -> Unit,
) {
    LazyVerticalGrid(
        columns = GridCells.Adaptive(minSize = 260.dp),
        contentPadding = PaddingValues(16.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        items(items, key = { it.id }) { s ->
            val code = codes[s.id]
            Surface(
                shape = RoundedCornerShape(22.dp),
                color = if (s.id == selectedId) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerLowest,
                modifier = Modifier.fillMaxWidth().clickable { onPick(s) },
            ) {
                Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    LetterTile(s.title, size = 40.dp)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(s.title, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
                        Text(code?.let { groupCode(it.code) } ?: "––– –––", style = CodeStyle.copy(fontSize = 26.sp))
                    }
                    if (code != null) TotpRing(code.remaining.toInt(), code.period.toInt(), size = 36.dp)
                }
            }
        }
        item(span = { GridItemSpan(maxLineSpan) }) {
            Text(
                "Tap a code to copy it.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(8.dp),
            )
        }
    }
}
