package dev.passwordvault.app

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import dev.passwordvault.app.data.VaultRepository

class VaultApp : Application() {
    lateinit var vault: VaultRepository
        private set

    override fun onCreate() {
        super.onCreate()
        vault = VaultRepository(this)
        ProcessLifecycleOwner.get().lifecycle.addObserver(AutoLock(vault))
    }
}

/**
 * Locks the vault after the app has been in the background longer than the
 * auto-lock setting, and merges the synced copy when the app comes back.
 */
private class AutoLock(private val vault: VaultRepository) : DefaultLifecycleObserver {
    private var hiddenAt = 0L

    override fun onStop(owner: LifecycleOwner) {
        hiddenAt = SystemClock.elapsedRealtime()
        if (vault.settings.autoLockSeconds == 0) vault.lock()
    }

    override fun onStart(owner: LifecycleOwner) {
        if (hiddenAt == 0L) return
        val away = (SystemClock.elapsedRealtime() - hiddenAt) / 1000
        if (away >= vault.settings.autoLockSeconds) vault.lock() else vault.syncInBackground()
    }
}
