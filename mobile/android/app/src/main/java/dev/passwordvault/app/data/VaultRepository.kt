package dev.passwordvault.app.data

import android.content.Context
import android.net.Uri
import androidx.fragment.app.FragmentActivity
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import uniffi.vault_mobile.ItemDetail
import uniffi.vault_mobile.ItemEdit
import uniffi.vault_mobile.ItemSummary
import uniffi.vault_mobile.LockedVault
import uniffi.vault_mobile.MobileException
import uniffi.vault_mobile.SlotInfo
import uniffi.vault_mobile.TotpCode
import uniffi.vault_mobile.VaultSession
import uniffi.vault_mobile.cloudJoin
import uniffi.vault_mobile.cloudLeave
import uniffi.vault_mobile.createVault

/** Where the app is: no vault yet, locked, or open. */
sealed interface VaultState {
    data object NoVault : VaultState
    data class Locked(val quickUnlock: Boolean, val hasPassword: Boolean) : VaultState
    data object Unlocked : VaultState
}

/** The state of the folder sync, for the status pill and Settings. */
data class SyncStatus(
    val enabled: Boolean = false,
    val lastSyncMillis: Long = 0,
    val error: String? = null,
    val needsPassword: Boolean = false,
    val conflicts: Int = 0,
)

/** The state of cloud sync, for Settings. `server` is null when it is off. */
data class CloudStatus(
    val server: String? = null,
    val busy: Boolean = false,
    val lastSyncMillis: Long = 0,
    val error: String? = null,
    val needsPassword: Boolean = false,
    val conflicts: Int = 0,
)

/**
 * The one vault on this phone: its file, its unlocked session and the
 * folder and cloud sync. Every call that runs Argon2, touches files or uses
 * the network is a suspend function on [Dispatchers.IO]/[Dispatchers.Default].
 */
class VaultRepository(private val context: Context) {
    val settings = Settings(context)
    val quickUnlock = QuickUnlock(context)

    private val cloudAccess = CloudAccessStore(context)
    private val cloudBook = CloudBookkeeping(settings)

    /** One cloud sync, join or leave at a time. Taken before [lock], never inside it. */
    private val cloudLock = Mutex()

    /** Goes up when cloud sync is turned off or replaced, so a sync still running is dropped. */
    @Volatile private var cloudEpoch = 0

    private val file = File(context.filesDir, "vault.svault")
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Mutex()

    @Volatile private var session: VaultSession? = null

    private val _state = MutableStateFlow<VaultState>(VaultState.NoVault)
    val state: StateFlow<VaultState> = _state.asStateFlow()

    private val _items = MutableStateFlow<List<ItemSummary>>(emptyList())
    val items: StateFlow<List<ItemSummary>> = _items.asStateFlow()

    private val _sync = MutableStateFlow(SyncStatus())
    val sync: StateFlow<SyncStatus> = _sync.asStateFlow()

    private val _cloud = MutableStateFlow(CloudStatus())
    val cloud: StateFlow<CloudStatus> = _cloud.asStateFlow()

    /** Bumped on every change so open detail screens reload. */
    private val _revision = MutableStateFlow(0L)
    val revision: StateFlow<Long> = _revision.asStateFlow()

    init {
        refreshState()
    }

    private fun refreshState() {
        _sync.update { it.copy(enabled = settings.syncUri != null) }
        _cloud.update { it.copy(server = if (cloudAccess.isOn) settings.cloudServer ?: "your sync server" else null) }
        if (session != null) {
            _state.value = VaultState.Unlocked
            return
        }
        val locked = readLocked()
        _state.value = if (locked == null) {
            VaultState.NoVault
        } else {
            VaultState.Locked(
                quickUnlock = quickUnlock.isEnabled && !fullUnlockDue(),
                hasPassword = locked.hasPasswordSlot(),
            )
        }
    }

    /** Quick unlock needs the master password again after 14 days. */
    fun fullUnlockDue(): Boolean =
        System.currentTimeMillis() - settings.lastFullUnlockMillis > FULL_UNLOCK_EVERY_MS

    private fun readLocked(): LockedVault? = try {
        if (file.exists()) LockedVault(file.readBytes()) else null
    } catch (e: MobileException) {
        null
    }

    // ---- creating and joining -------------------------------------------

    /** Create a vault; returns the recovery code to show once. */
    suspend fun create(password: String): String = withContext(Dispatchers.Default) {
        lock.withLock {
            check(!file.exists()) { "a vault already exists" }
            val nv = createVault(password, settings.deviceId)
            session = nv.session
            writeLocal(nv.session.toBytes())
            settings.lastFullUnlockMillis = System.currentTimeMillis()
            afterOpen()
            nv.recoveryCode
        }
    }

    /**
     * Join a vault kept in a cloud folder: copy the synced file and keep it
     * merged from then on. Unlock it afterwards with its master password.
     */
    suspend fun join(uri: Uri) = withContext(Dispatchers.IO) {
        lock.withLock {
            val bytes = readUri(uri)
            LockedVault(bytes) // throws if it is not a vault
            writeLocal(bytes)
            settings.syncUri = uri
            refreshState()
        }
    }

    // ---- unlocking ----------------------------------------------------------

    suspend fun unlockPassword(password: String) = openWith(full = true) { locked ->
        locked.unlockPassword(password, settings.deviceId)
    }

    suspend fun unlockRecovery(code: String) = openWith(full = true) { locked ->
        locked.unlockRecovery(code, settings.deviceId)
    }

    suspend fun unlockBiometric(activity: FragmentActivity) {
        val (wrap, parked) = quickUnlock.unwrap(activity)
        try {
            openWith(full = false) { locked -> locked.resume(parked, wrap, settings.deviceId) }
        } catch (e: MobileException) {
            // The key was rotated on another device, or the file replaced.
            quickUnlock.disable()
            refreshState()
            throw e
        } finally {
            wrap.fill(0)
        }
    }

    private suspend fun openWith(full: Boolean, open: (LockedVault) -> VaultSession) =
        withContext(Dispatchers.Default) {
            lock.withLock {
                val locked = readLocked() ?: throw IOException("The vault file is missing.")
                session = open(locked)
                if (full) settings.lastFullUnlockMillis = System.currentTimeMillis()
            }
            afterOpen()
            syncFolderNow()
            // The vault is usable at once; the network can take its time.
            cloudSyncInBackground()
        }

    private fun afterOpen() {
        val s = session ?: return
        val gen = s.generation().toLong()
        if (gen > settings.highestGeneration) settings.highestGeneration = gen
        reloadItems()
        _state.value = VaultState.Unlocked
    }

    /** Turn on fingerprint or face unlock for the open vault. */
    suspend fun enableQuickUnlock(activity: FragmentActivity) {
        val s = session ?: return
        quickUnlock.enable(activity) { wrap -> s.park(wrap) }
    }

    fun lock() {
        session?.destroy()
        session = null
        _items.value = emptyList()
        refreshState()
    }

    val isUnlocked: Boolean get() = session != null

    // ---- reading and editing --------------------------------------------

    private fun reloadItems() {
        _items.value = session?.items().orEmpty()
        _revision.update { it + 1 }
    }

    fun item(id: String): ItemDetail? = try {
        session?.item(id)
    } catch (e: MobileException.NotFound) {
        null
    }

    fun totp(id: String): TotpCode? =
        session?.totp(id, (System.currentTimeMillis() / 1000).toULong())

    fun loginsFor(domain: String): List<ItemSummary> = session?.loginsFor(domain).orEmpty()

    fun slots(): List<SlotInfo> = session?.slots().orEmpty()

    /** Create (`id` null) or update an item; returns its ID. */
    suspend fun save(id: String?, edit: ItemEdit): String = withContext(Dispatchers.IO) {
        lock.withLock {
            val s = session ?: throw IllegalStateException("locked")
            mergeFolder(s, null)
            val newId = s.saveItem(id, edit)
            persist(s)
            newId
        }
    }

    /** Add a one-time code to the login [to], or to a new login; returns its ID. */
    suspend fun addCode(input: String, title: String, account: String, to: String?): String = withContext(Dispatchers.IO) {
        lock.withLock {
            val s = session ?: throw IllegalStateException("locked")
            mergeFolder(s, null)
            val id = s.addCode(input, title, account, to)
            persist(s)
            id
        }
    }

    suspend fun delete(id: String) = withContext(Dispatchers.IO) {
        lock.withLock {
            val s = session ?: return@withLock
            mergeFolder(s, null)
            s.deleteItem(id)
            persist(s)
        }
    }

    // ---- files ----------------------------------------------------------------

    private fun persist(s: VaultSession) {
        val bytes = s.toBytes()
        writeLocal(bytes)
        settings.syncUri?.let { uri ->
            runCatching { writeUri(uri, bytes) }
                .onFailure { e -> _sync.update { it.copy(error = "Could not write the synced copy: ${e.message}") } }
        }
        reloadItems()
        if (cloudAccess.isOn) {
            cloudBook.changed()
            cloudSyncInBackground()
        }
    }

    private fun writeLocal(bytes: ByteArray) {
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(bytes)
        if (!tmp.renameTo(file)) throw IOException("could not save the vault")
    }

    private fun readUri(uri: Uri): ByteArray =
        context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw FileNotFoundException("The synced file could not be opened.")

    private fun writeUri(uri: Uri, bytes: ByteArray) {
        context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) }
            ?: throw FileNotFoundException("The synced file could not be written.")
    }

    // ---- sync -------------------------------------------------------------------

    /** Use [uri] (picked with the system file picker) as the synced copy. */
    suspend fun setSyncFile(uri: Uri?, create: Boolean) = withContext(Dispatchers.IO) {
        lock.withLock {
            settings.syncUri = uri
            _sync.value = SyncStatus(enabled = uri != null)
            val s = session
            if (uri != null && s != null && create) writeUri(uri, s.toBytes())
        }
        syncNow()
    }

    /** Sync now, folder and cloud. Pass the master password after a re-key. */
    suspend fun syncNow(password: String? = null) {
        syncFolderNow(password)
        syncCloudNow(password)
    }

    private suspend fun syncFolderNow(password: String? = null) = withContext(Dispatchers.IO) {
        lock.withLock {
            val s = session ?: return@withLock
            mergeFolder(s, password)
        }
    }

    fun syncInBackground() {
        scope.launch { runCatching { syncNow() } }
    }

    // ---- cloud sync -------------------------------------------------------------

    private fun cloudSyncInBackground() {
        if (cloudAccess.isOn) scope.launch { runCatching { syncCloudNow() } }
    }

    /**
     * Merge with the sync server's copy and upload when it lacks something.
     * The vault stays usable meanwhile: only the file writes take [lock].
     */
    suspend fun syncCloudNow(password: String? = null) = withContext(Dispatchers.IO) {
        cloudLock.withLock {
            // Again while something was saved during the previous round.
            var rounds = 0
            while (rounds++ < 3 && cloudRound(password)) Unit
        }
    }

    /** One exchange with the server; true when another is due at once. */
    private suspend fun cloudRound(password: String?): Boolean {
        val s = session ?: return false
        if (!cloudAccess.isOn) return false
        val access = cloudAccess.read()
        if (access == null) {
            _cloud.update { it.copy(error = "This phone's cloud sync access can't be read. Stop cloud sync and join again with a new link.") }
            return false
        }
        val epoch = cloudEpoch
        val ticket = cloudBook.begin()
        _cloud.update { it.copy(busy = true) }
        try {
            val r = s.cloudSync(access, ticket.known?.toULong(), ticket.dirty, password)
            var more = false
            lock.withLock {
                // Locked, removed or turned off meanwhile: leave the file alone
                // and the version as it was, so the next sync fetches again.
                if (epoch != cloudEpoch || session !== s) return false
                if (r.changed) {
                    writeLocal(s.toBytes())
                    settings.syncUri?.let { uri -> runCatching { writeUri(uri, s.toBytes()) } }
                    reloadItems()
                }
                more = cloudBook.finished(ticket, r.version.toLong())
            }
            _cloud.update {
                it.copy(
                    lastSyncMillis = System.currentTimeMillis(),
                    error = null,
                    needsPassword = false,
                    conflicts = it.conflicts + r.conflicts.toInt(),
                )
            }
            return more
        } catch (e: CancellationException) {
            throw e
        } catch (e: MobileException.Rekeyed) {
            if (epoch == cloudEpoch) _cloud.update { it.copy(error = e.message, needsPassword = true) }
        } catch (e: Exception) {
            // A session destroyed by locking ends up here too; nothing to report then.
            if (epoch == cloudEpoch && session === s) _cloud.update { it.copy(error = e.message) }
        } finally {
            _cloud.update { it.copy(busy = false) }
        }
        return false
    }

    private fun deviceName(): String =
        if (context.resources.configuration.smallestScreenWidthDp >= 600) "Android tablet" else "Android phone"

    /**
     * Join cloud sync with a link from a computer when there is no vault here
     * yet: keep this phone's access and the downloaded vault, which then
     * opens with the master password.
     */
    suspend fun joinCloud(link: String) = withContext(Dispatchers.IO) {
        cloudLock.withLock {
            val j = cloudJoin(link, deviceName())
            var kept = false
            try {
                val bytes = j.file ?: throw IOException(
                    "The vault is not on the server yet. Open the vault on your computer with its sync helper running, then make a new link.",
                )
                LockedVault(bytes).destroy() // throws if it is not a vault
                lock.withLock {
                    check(!file.exists()) { "a vault already exists" }
                    writeLocal(bytes)
                    keepAccess(j.access, j.server, j.version?.toLong(), upload = false)
                }
                kept = true
            } finally {
                // Don't leave a device on the server that this phone forgot.
                if (!kept) runCatching { cloudLeave(j.access) }
            }
            refreshState()
        }
    }

    /**
     * Turn cloud sync on for the open vault with a link from a computer. The
     * vault on the server must be this one; the two are merged.
     */
    suspend fun addCloud(link: String) {
        withContext(Dispatchers.IO) {
            cloudLock.withLock {
                val s = session ?: throw IllegalStateException("locked")
                val j = cloudJoin(link, deviceName())
                var kept = false
                try {
                    j.file?.let { bytes ->
                        val theirs = LockedVault(bytes)
                        val same = try { theirs.vaultId() == s.vaultId() } finally { theirs.destroy() }
                        if (!same) throw IOException(
                            "The vault on that server is a different vault from the one on this phone. Remove this one first (Settings, Remove the vault from this device) to use that one.",
                        )
                    }
                    keepAccess(j.access, j.server, version = null, upload = true)
                    kept = true
                } finally {
                    if (!kept) runCatching { cloudLeave(j.access) }
                }
                refreshState()
            }
        }
        syncCloudNow()
    }

    private fun keepAccess(access: String, server: String, version: Long?, upload: Boolean) {
        cloudEpoch++
        cloudAccess.save(access)
        settings.cloudServer = server
        cloudBook.reset(version, upload)
        _cloud.value = CloudStatus(server = server)
    }

    /**
     * Stop cloud sync here: this phone's access on the server is deleted, in
     * the background; the vault stays on this phone and on the server.
     */
    fun leaveCloud() {
        if (!cloudAccess.isOn) return
        val access = cloudAccess.read()
        cloudEpoch++
        cloudAccess.clear()
        settings.cloudServer = null
        cloudBook.reset(version = null, upload = false)
        _cloud.value = CloudStatus()
        if (access != null) scope.launch { runCatching { cloudLeave(access) } }
    }

    private fun mergeFolder(s: VaultSession, password: String?) {
        val uri = settings.syncUri ?: return
        val theirs = try {
            readUri(uri)
        } catch (e: Exception) {
            _sync.update { it.copy(error = "Could not read the synced copy: ${e.message}") }
            return
        }
        try {
            val r = s.merge(theirs, password)
            if (r.changed) {
                writeLocal(s.toBytes())
                reloadItems()
                // What came from the folder goes to the sync server too.
                if (cloudAccess.isOn) cloudBook.changed()
            }
            if (r.changed || r.otherBehind) writeUri(uri, s.toBytes())
            _sync.update {
                it.copy(
                    lastSyncMillis = System.currentTimeMillis(),
                    error = null,
                    needsPassword = false,
                    conflicts = it.conflicts + r.conflicts.toInt(),
                )
            }
        } catch (e: MobileException.Rekeyed) {
            _sync.update { it.copy(error = e.message, needsPassword = true) }
        } catch (e: MobileException.BadFile) {
            // Half-downloaded by the cloud app; try again next time.
            _sync.update { it.copy(error = "The synced copy is incomplete; trying again later.") }
        } catch (e: MobileException) {
            _sync.update { it.copy(error = e.message) }
        }
    }

    // ---- reset ------------------------------------------------------------------

    /** Remove the vault from this phone (the synced copy is left alone). */
    fun removeFromDevice() {
        leaveCloud()
        lock()
        quickUnlock.disable()
        file.delete()
        settings.syncUri = null
        refreshState()
    }

    companion object {
        const val FULL_UNLOCK_EVERY_MS = 14L * 24 * 60 * 60 * 1000
    }
}
