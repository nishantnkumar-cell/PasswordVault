package dev.passwordvault.app.data

/**
 * What this phone knows about the sync server's copy: its version after the
 * last sync, and whether this phone has changes the server lacks. Nothing
 * here is secret.
 *
 * Changes are counted, so that something saved while a sync is on its way is
 * not mistaken for uploaded.
 */
class CloudBookkeeping(private val store: Store) {
    interface Store {
        var cloudVersion: Long?
        var cloudDirty: Boolean
        var cloudChanges: Long
    }

    /** What was true when a sync started. */
    data class Ticket(val known: Long?, val dirty: Boolean, val changes: Long)

    /** Something was saved here that the server does not have yet. */
    @Synchronized
    fun changed() {
        store.cloudChanges += 1
        store.cloudDirty = true
    }

    @Synchronized
    fun begin() = Ticket(store.cloudVersion, store.cloudDirty, store.cloudChanges)

    /**
     * The sync that started with [ticket] left the server at [version].
     * Returns true when something was saved meanwhile, so another sync is due.
     */
    @Synchronized
    fun finished(ticket: Ticket, version: Long): Boolean {
        store.cloudVersion = version
        val more = store.cloudChanges != ticket.changes
        store.cloudDirty = more
        return more
    }

    /** Start over: [upload] when this phone's vault should be sent at the next sync. */
    @Synchronized
    fun reset(version: Long?, upload: Boolean) {
        store.cloudVersion = version
        store.cloudDirty = upload
    }
}
