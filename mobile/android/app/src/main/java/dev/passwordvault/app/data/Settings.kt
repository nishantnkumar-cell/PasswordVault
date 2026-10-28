package dev.passwordvault.app.data

import android.content.Context
import android.net.Uri
import java.security.SecureRandom

/** App preferences. Nothing here is secret. */
class Settings(context: Context) {
    private val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    /** This phone's ID in each item's version vector (docs/sync.md). */
    val deviceId: ULong
        get() {
            var id = prefs.getLong(KEY_DEVICE, 0L)
            while (id == 0L) {
                id = SecureRandom().nextLong()
                prefs.edit().putLong(KEY_DEVICE, id).apply()
            }
            return id.toULong()
        }

    /** Lock after this long in the background. 0 = as soon as the app is hidden. */
    var autoLockSeconds: Int
        get() = prefs.getInt(KEY_AUTOLOCK, 300)
        set(v) = prefs.edit().putInt(KEY_AUTOLOCK, v).apply()

    /** Clear copied secrets from the clipboard after this long. */
    var clipboardSeconds: Int
        get() = prefs.getInt(KEY_CLIPBOARD, 60)
        set(v) = prefs.edit().putInt(KEY_CLIPBOARD, v).apply()

    /** Follow the wallpaper colours (Android 12+) instead of the vault palette. */
    var dynamicColor: Boolean
        get() = prefs.getBoolean(KEY_DYNAMIC, false)
        set(v) = prefs.edit().putBoolean(KEY_DYNAMIC, v).apply()

    /** The synced copy in a cloud folder, picked through the system file picker. */
    var syncUri: Uri?
        get() = prefs.getString(KEY_SYNC, null)?.let(Uri::parse)
        set(v) = prefs.edit().putString(KEY_SYNC, v?.toString()).apply()

    /** When the vault was last opened with the master password or recovery code. */
    var lastFullUnlockMillis: Long
        get() = prefs.getLong(KEY_FULL_UNLOCK, 0L)
        set(v) = prefs.edit().putLong(KEY_FULL_UNLOCK, v).apply()

    /** The highest generation seen, to warn when an older copy is opened. */
    var highestGeneration: Long
        get() = prefs.getLong(KEY_GENERATION, 0L)
        set(v) = prefs.edit().putLong(KEY_GENERATION, v).apply()

    /** The generator's style: "random", "words" or "apple". */
    var generatorStyle: String
        get() = prefs.getString(KEY_GEN_STYLE, "random") ?: "random"
        set(v) = prefs.edit().putString(KEY_GEN_STYLE, v).apply()

    /** Words for the "words" style, 3 to 10. */
    var generatorWords: Int
        get() = prefs.getInt(KEY_GEN_WORDS, 3)
        set(v) = prefs.edit().putInt(KEY_GEN_WORDS, v).apply()

    /** What goes between words; empty runs them together. */
    var generatorSeparator: String
        get() = prefs.getString(KEY_GEN_SEPARATOR, "") ?: ""
        set(v) = prefs.edit().putString(KEY_GEN_SEPARATOR, v).apply()

    var generatorCapitalize: Boolean
        get() = prefs.getBoolean(KEY_GEN_CAPITALIZE, true)
        set(v) = prefs.edit().putBoolean(KEY_GEN_CAPITALIZE, v).apply()

    var generatorNumberAndSymbol: Boolean
        get() = prefs.getBoolean(KEY_GEN_EXTRA, false)
        set(v) = prefs.edit().putBoolean(KEY_GEN_EXTRA, v).apply()

    private companion object {
        const val KEY_DEVICE = "device_id"
        const val KEY_AUTOLOCK = "autolock_seconds"
        const val KEY_CLIPBOARD = "clipboard_seconds"
        const val KEY_DYNAMIC = "dynamic_color"
        const val KEY_SYNC = "sync_uri"
        const val KEY_FULL_UNLOCK = "full_unlock_at"
        const val KEY_GENERATION = "highest_generation"
        const val KEY_GEN_STYLE = "generator_style"
        const val KEY_GEN_WORDS = "generator_words"
        const val KEY_GEN_SEPARATOR = "generator_separator"
        const val KEY_GEN_CAPITALIZE = "generator_capitalize"
        const val KEY_GEN_EXTRA = "generator_number_symbol"
    }
}
