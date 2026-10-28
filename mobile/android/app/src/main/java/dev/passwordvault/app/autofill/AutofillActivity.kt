package dev.passwordvault.app.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.IntentCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.passwordvault.app.VaultApp
import dev.passwordvault.app.data.VaultRepository
import dev.passwordvault.app.data.VaultState
import dev.passwordvault.app.ui.components.LetterTile
import dev.passwordvault.app.ui.components.segmentShape
import dev.passwordvault.app.ui.items.matches
import dev.passwordvault.app.ui.theme.Mono
import dev.passwordvault.app.ui.theme.VaultTheme
import dev.passwordvault.app.ui.unlock.UnlockScreen
import uniffi.vault_mobile.ItemSummary
import uniffi.vault_mobile.Kind

/**
 * Opened from the autofill suggestion "Unlock / Search Secret Vault": unlock
 * if needed, then pick the login to fill.
 */
class AutofillActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        val vault = (application as VaultApp).vault
        val target = FillTarget(
            username = IntentCompat.getParcelableExtra(intent, EXTRA_USER, AutofillId::class.java),
            password = IntentCompat.getParcelableExtra(intent, EXTRA_PASS, AutofillId::class.java),
            webDomain = intent.getStringExtra(EXTRA_DOMAIN),
            packageName = intent.getStringExtra(EXTRA_PACKAGE).orEmpty(),
        )
        setContent {
            VaultTheme(dynamicColor = vault.settings.dynamicColor) {
                val state by vault.state.collectAsStateWithLifecycle()
                if (state is VaultState.Locked) {
                    UnlockScreen(vault, state as VaultState.Locked)
                } else {
                    Picker(vault, target, onPick = ::fill, onCancel = ::finish)
                }
            }
        }
    }

    private fun fill(target: FillTarget, item: ItemSummary) {
        val vault = (application as VaultApp).vault
        val detail = vault.item(item.id) ?: return finish()
        val dataset = VaultAutofillService.dataset(this, target, detail, item.title, item.subtitle)
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
        finish()
    }

    companion object {
        private const val EXTRA_USER = "user"
        private const val EXTRA_PASS = "pass"
        private const val EXTRA_DOMAIN = "domain"
        private const val EXTRA_PACKAGE = "package"

        fun intentSender(context: Context, target: FillTarget): IntentSender {
            val intent = Intent(context, AutofillActivity::class.java)
                .putExtra(EXTRA_USER, target.username)
                .putExtra(EXTRA_PASS, target.password)
                .putExtra(EXTRA_DOMAIN, target.webDomain)
                .putExtra(EXTRA_PACKAGE, target.packageName)
            // Mutable: Android adds the screen's structure to the intent.
            val flags = PendingIntent.FLAG_CANCEL_CURRENT or
                (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0)
            return PendingIntent.getActivity(context, target.hashCode(), intent, flags).intentSender
        }
    }
}

@Composable
private fun Picker(vault: VaultRepository, target: FillTarget, onPick: (FillTarget, ItemSummary) -> Unit, onCancel: () -> Unit) {
    val all by vault.items.collectAsStateWithLifecycle()
    var query by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf<ItemSummary?>(null) }
    val matching = remember(all, target) { target.webDomain?.let { vault.loginsFor(it) }.orEmpty() }
    val matchIds = remember(matching) { matching.map { it.id }.toSet() }
    val others = remember(all, query, matchIds) {
        all.filter { it.kind == Kind.LOGIN && it.id !in matchIds && query.isNotBlank() && it.matches(query) }
    }
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.BottomCenter) {
        Surface(
            shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
            color = MaterialTheme.colorScheme.surfaceContainer,
            modifier = Modifier.widthIn(max = 640.dp).fillMaxWidth().fillMaxHeight(0.75f),
        ) {
            Column(Modifier.padding(16.dp).navigationBarsPadding(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Secret Vault", style = MaterialTheme.typography.titleLarge)
                        Text(
                            target.webDomain?.let { "Logins for $it" } ?: "Filling in ${target.packageName}",
                            fontFamily = if (target.webDomain != null) Mono else null,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    TextButton(onClick = onCancel) { Text("Cancel") }
                }
                OutlinedTextField(
                    value = query, onValueChange = { query = it },
                    label = { Text("Search all logins") }, singleLine = true,
                    shape = MaterialTheme.shapes.medium, modifier = Modifier.fillMaxWidth(),
                )
                LazyColumn(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    itemsIndexed(matching, key = { _, it -> "m" + it.id }) { i, s ->
                        PickRow(s, segmentShape(i, matching.size), exact = true) { onPick(target, s) }
                    }
                    itemsIndexed(others, key = { _, it -> "o" + it.id }) { i, s ->
                        PickRow(s, segmentShape(i, others.size), exact = false) { confirm = s }
                    }
                }
                if (matching.isEmpty() && query.isBlank()) {
                    Text(
                        if (target.webDomain == null) "Apps don't prove which website they belong to, so nothing is suggested. Search for the login to fill."
                        else "No login is bound to this site. Search to pick one anyway.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
    confirm?.let { s ->
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text("Fill ${s.title} here?") },
            text = {
                Text(
                    "This login is not bound to " + (target.webDomain ?: target.packageName) +
                        ". Only continue if you are sure this is the right place; look-alike sites steal passwords this way.",
                )
            },
            confirmButton = { TextButton(onClick = { confirm = null; onPick(target, s) }) { Text("Fill") } },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun PickRow(s: ItemSummary, shape: androidx.compose.ui.graphics.Shape, exact: Boolean, onClick: () -> Unit) {
    Surface(shape = shape, color = MaterialTheme.colorScheme.surfaceContainerLowest, modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            LetterTile(s.title, size = 40.dp)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(s.title, style = MaterialTheme.typography.titleMedium)
                Text(s.subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (exact) {
                Text("Exact site", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.tertiary)
            }
        }
    }
}
