package dev.passwordvault.app.ui.components

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Copies a value, marked sensitive so Android hides it in the clipboard
 * preview and keyboard suggestions, and clears it after [clearAfterSeconds]
 * unless something else was copied meanwhile.
 */
object SecureClipboard {
    private val handler = Handler(Looper.getMainLooper())
    private var pending: Runnable? = null

    fun copy(context: Context, label: String, value: String, sensitive: Boolean, clearAfterSeconds: Int) {
        val cm = context.getSystemService(ClipboardManager::class.java) ?: return
        val clip = ClipData.newPlainText(label, value)
        if (sensitive) {
            clip.description.extras = PersistableBundle().apply {
                val key = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    ClipDescription.EXTRA_IS_SENSITIVE
                } else {
                    "android.content.extra.IS_SENSITIVE"
                }
                putBoolean(key, true)
            }
        }
        cm.setPrimaryClip(clip)
        pending?.let(handler::removeCallbacks)
        if (!sensitive || clearAfterSeconds <= 0) return
        val r = Runnable {
            val current = runCatching { cm.primaryClip?.getItemAt(0)?.text?.toString() }.getOrNull()
            if (current == value) clear(context)
        }
        pending = r
        handler.postDelayed(r, clearAfterSeconds * 1000L)
    }

    fun clear(context: Context) {
        val cm = context.getSystemService(ClipboardManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) cm.clearPrimaryClip()
    }
}
