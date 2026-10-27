package dev.passwordvault.app.ui.items

import androidx.activity.compose.BackHandler
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
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.adaptive.ExperimentalMaterial3AdaptiveApi
import androidx.compose.material3.adaptive.layout.AnimatedPane
import androidx.compose.material3.adaptive.layout.ListDetailPaneScaffold
import androidx.compose.material3.adaptive.layout.ListDetailPaneScaffoldRole
import androidx.compose.material3.adaptive.layout.PaneAdaptedValue
import androidx.compose.material3.adaptive.navigation.rememberListDetailPaneScaffoldNavigator
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.passwordvault.app.data.VaultRepository
import dev.passwordvault.app.ui.components.LetterTile
import dev.passwordvault.app.ui.components.segmentShape
import kotlinx.coroutines.launch
import uniffi.vault_mobile.ItemSummary
import uniffi.vault_mobile.Kind

/** Category filters, as in the desktop sidebar. */
enum class Category(val label: String, val matches: (ItemSummary) -> Boolean) {
    All("All", { true }),
    Logins("Logins", { it.kind == Kind.LOGIN }),
    Cards("Cards", { it.kind == Kind.CARD }),
    Notes("Notes", { it.kind == Kind.NOTE && !it.hasKey }),
    Identities("Identities", { it.kind == Kind.IDENTITY }),
    Codes("One-time codes", { it.hasTotp }),
    Keys("Keys", { it.hasKey }),
}

fun ItemSummary.matches(q: String): Boolean {
    if (q.isBlank()) return true
    val n = q.trim().lowercase()
    return title.lowercase().contains(n) || subtitle.lowercase().contains(n) || (host?.contains(n) == true)
}

/** Detail pane keys: an item ID, or "new:<kind>" for the editor. */
private const val NEW = "new:"

/**
 * List and detail. ListDetailPaneScaffold shows one pane on phones and two
 * side by side on tablets, open foldables and dual screens, keeping both
 * panes clear of a hinge.
 */
@OptIn(ExperimentalMaterial3AdaptiveApi::class)
@Composable
fun ItemsScreen(vault: VaultRepository) {
    val navigator = rememberListDetailPaneScaffoldNavigator<String>()
    val scope = rememberCoroutineScope()
    val twoPane = navigator.scaffoldValue[ListDetailPaneScaffoldRole.List] == PaneAdaptedValue.Expanded &&
        navigator.scaffoldValue[ListDetailPaneScaffoldRole.Detail] == PaneAdaptedValue.Expanded
    fun open(key: String) = scope.launch { navigator.navigateTo(ListDetailPaneScaffoldRole.Detail, key) }
    fun back() = scope.launch { navigator.navigateBack() }

    BackHandler(navigator.canNavigateBack()) { back() }

    ListDetailPaneScaffold(
        directive = navigator.scaffoldDirective,
        value = navigator.scaffoldValue,
        listPane = {
            AnimatedPane {
                ItemList(
                    vault = vault,
                    selected = navigator.currentDestination?.contentKey,
                    onOpen = { open(it) },
                    onNew = { kind -> open(NEW + kind.name) },
                )
            }
        },
        detailPane = {
            AnimatedPane {
                val key = navigator.currentDestination?.contentKey
                when {
                    key == null -> EmptyDetail()
                    key.startsWith(NEW) -> ItemEditor(
                        vault = vault,
                        id = null,
                        newKind = Kind.valueOf(key.removePrefix(NEW)),
                        showBack = !twoPane,
                        onDone = { saved -> if (saved != null) open(saved) else back() },
                    )
                    else -> ItemDetailPane(vault, key, showBack = !twoPane, onBack = { back() }, onDeleted = { back() })
                }
            }
        },
    )
}

@Composable
private fun ItemList(
    vault: VaultRepository,
    selected: String?,
    onOpen: (String) -> Unit,
    onNew: (Kind) -> Unit,
) {
    val items by vault.items.collectAsStateWithLifecycle()
    var query by rememberSaveable { mutableStateOf("") }
    var category by rememberSaveable { mutableStateOf(Category.All) }
    var menu by remember { mutableStateOf(false) }
    val shown = remember(items, query, category) { items.filter { category.matches(it) && it.matches(query) } }

    Box(Modifier.fillMaxSize()) {
        LazyColumn(
            Modifier.fillMaxSize().statusBarsPadding(),
            contentPadding = PaddingValues(start = 12.dp, end = 12.dp, bottom = 112.dp),
        ) {
            item { SearchPill(query, { query = it }, onLock = vault::lock) }
            item {
                LazyRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 8.dp),
                ) {
                    items(Category.entries) { c ->
                        val n = items.count(c.matches)
                        if (c == Category.All || n > 0) {
                            FilterChip(
                                selected = c == category,
                                onClick = { category = c },
                                label = { Text(c.label) },
                                shape = MaterialTheme.shapes.small,
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                                ),
                            )
                        }
                    }
                }
            }
            item {
                Text(
                    "${category.label} · ${shown.size}",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(start = 16.dp, top = 4.dp, bottom = 10.dp),
                )
            }
            if (shown.isEmpty()) {
                item {
                    Text(
                        if (items.isEmpty()) "No items yet. Tap New item to add your first login." else "Nothing matches.",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(16.dp),
                    )
                }
            }
            itemsIndexed(shown, key = { _, it -> it.id }) { i, it ->
                ItemRow(it, selected = it.id == selected, shape = segmentShape(i, shown.size)) { onOpen(it.id) }
                Spacer(Modifier.height(3.dp))
            }
        }
        Box(Modifier.align(Alignment.BottomEnd).padding(16.dp)) {
            ExtendedFloatingActionButton(
                onClick = { menu = true },
                icon = { Icon(Icons.Outlined.Add, contentDescription = null) },
                text = { Text("New item") },
            )
            DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                listOf(Kind.LOGIN to "Login", Kind.NOTE to "Secure note", Kind.CARD to "Card", Kind.IDENTITY to "Identity")
                    .forEach { (k, label) ->
                        DropdownMenuItem(text = { Text(label) }, onClick = { menu = false; onNew(k) })
                    }
            }
        }
    }
}

@Composable
private fun SearchPill(query: String, onQuery: (String) -> Unit, onLock: () -> Unit) {
    Surface(
        shape = CircleShape,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp).height(56.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(start = 18.dp, end = 6.dp)) {
            Icon(Icons.Outlined.Search, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.width(12.dp))
            Box(Modifier.weight(1f)) {
                if (query.isEmpty()) {
                    Text("Search vault", style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                BasicTextField(
                    value = query,
                    onValueChange = onQuery,
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyLarge.copy(color = MaterialTheme.colorScheme.onSurface),
                    cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (query.isNotEmpty()) {
                IconButton(onClick = { onQuery("") }) { Icon(Icons.Outlined.Close, contentDescription = "Clear search") }
            }
            Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primaryContainer, modifier = Modifier.size(44.dp)) {
                IconButton(onClick = onLock) {
                    Icon(Icons.Outlined.Lock, contentDescription = "Lock vault", tint = MaterialTheme.colorScheme.onPrimaryContainer)
                }
            }
        }
    }
}

@Composable
private fun ItemRow(item: ItemSummary, selected: Boolean, shape: androidx.compose.ui.graphics.Shape, onClick: () -> Unit) {
    Surface(
        shape = shape,
        color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerLowest,
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
    ) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            LetterTile(item.title)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(item.title, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                val sub = item.subtitle.ifEmpty { kindLabel(item.kind) }
                Text(sub, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            val tag = when {
                item.hasKey -> "Key"
                item.hasTotp -> "2FA"
                else -> null
            }
            if (tag != null) {
                Surface(shape = MaterialTheme.shapes.extraSmall, color = MaterialTheme.colorScheme.primaryContainer) {
                    Text(
                        tag,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                    )
                }
            }
        }
    }
}

fun kindLabel(k: Kind) = when (k) {
    Kind.LOGIN -> "Login"
    Kind.NOTE -> "Secure note"
    Kind.CARD -> "Card"
    Kind.IDENTITY -> "Identity"
}

@Composable
private fun EmptyDetail() {
    Box(Modifier.fillMaxSize().safeDrawingPadding(), contentAlignment = Alignment.Center) {
        Text("Pick an item", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
