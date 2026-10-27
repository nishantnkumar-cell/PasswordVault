package dev.passwordvault.app.autofill

import android.app.assist.AssistStructure
import android.content.Context
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import dev.passwordvault.app.R
import dev.passwordvault.app.VaultApp
import uniffi.vault_mobile.ItemDetail

/** The fields to fill on a screen and where the screen came from. */
data class FillTarget(
    val username: AutofillId?,
    val password: AutofillId?,
    /** The web page's domain as the browser reported it; null in native apps. */
    val webDomain: String?,
    val packageName: String,
) {
    val ids: List<AutofillId> get() = listOfNotNull(username, password)
}

/**
 * Android autofill. Logins are suggested only for a web page whose domain
 * the browser reported and that the login is bound to, with the same origin
 * rules as the browser extension. In other apps, and when nothing matches,
 * the only suggestion is "Search Secret Vault", which opens the vault so the
 * user picks a login on purpose.
 */
class VaultAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, cancel: CancellationSignal, callback: FillCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess(null)
        val target = parse(structure)
        if (target.ids.isEmpty() || target.packageName == packageName) return callback.onSuccess(null)
        val vault = (application as VaultApp).vault
        val response = FillResponse.Builder()
        if (vault.isUnlocked && target.webDomain != null) {
            vault.loginsFor(target.webDomain).take(5).forEach { s ->
                vault.item(s.id)?.let { response.addDataset(dataset(this, target, it, s.title, s.subtitle)) }
            }
        }
        // Always offer to open the vault: to unlock it, or to pick by hand.
        val label = if (vault.isUnlocked) getString(R.string.autofill_search) else getString(R.string.autofill_unlock)
        @Suppress("DEPRECATION")
        val open = Dataset.Builder(presentation(this, label, target.webDomain ?: ""))
        target.ids.forEach { open.setValue(it, null) }
        open.setAuthentication(AutofillActivity.intentSender(this, target))
        response.addDataset(open.build())
        callback.onSuccess(response.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Saving from other apps is not offered yet (docs/mobile.md).
        callback.onSuccess()
    }

    companion object {
        fun presentation(context: Context, title: String, subtitle: String): RemoteViews =
            RemoteViews(context.packageName, android.R.layout.simple_list_item_2).apply {
                setTextViewText(android.R.id.text1, title)
                setTextViewText(android.R.id.text2, subtitle)
            }

        @Suppress("DEPRECATION")
        fun dataset(context: Context, target: FillTarget, item: ItemDetail, title: String, subtitle: String): Dataset {
            val b = Dataset.Builder(presentation(context, title, subtitle))
            target.username?.let { b.setValue(it, AutofillValue.forText(item.username)) }
            target.password?.let { b.setValue(it, AutofillValue.forText(item.password)) }
            return b.build()
        }

        fun parse(structure: AssistStructure): FillTarget {
            var user: AutofillId? = null
            var pass: AutofillId? = null
            var domain: String? = null
            fun visit(n: AssistStructure.ViewNode) {
                n.webDomain?.takeIf { it.isNotBlank() }?.let { if (domain == null) domain = it }
                val id = n.autofillId
                if (id != null && n.autofillType == View.AUTOFILL_TYPE_TEXT) {
                    val hints = n.autofillHints?.map { it.lowercase() }.orEmpty()
                    val words = listOfNotNull(n.idEntry, n.hint, n.htmlInfo?.attributes?.firstOrNull { it.first == "name" }?.second)
                        .joinToString(" ").lowercase()
                    val variation = n.inputType and InputType.TYPE_MASK_VARIATION
                    val isPassword = hints.any { View.AUTOFILL_HINT_PASSWORD in it } ||
                        variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                        variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
                        n.htmlInfo?.attributes?.any { it.first == "type" && it.second == View.AUTOFILL_HINT_PASSWORD } == true
                    val isUser = hints.any { it == View.AUTOFILL_HINT_USERNAME.lowercase() || it == View.AUTOFILL_HINT_EMAIL_ADDRESS.lowercase() || "username" in it || "email" in it } ||
                        variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
                        variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS ||
                        listOf("user", "email", "login", "account").any { it in words }
                    if (isPassword && pass == null) pass = id
                    else if (isUser && user == null && pass == null) user = id
                }
                for (i in 0 until n.childCount) visit(n.getChildAt(i))
            }
            for (i in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(i).rootViewNode)
            return FillTarget(user, pass, domain, structure.activityComponent.packageName)
        }
    }
}
