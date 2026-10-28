import AuthenticationServices
import Foundation
import Observation

/// The one vault on this device, shared by the app and the AutoFill
/// extension: its file, its unlocked session and the folder sync. Argon2
/// and file work run off the main actor.
@MainActor
@Observable
final class VaultModel {
    enum State: Equatable {
        case noVault
        case locked(quickUnlock: Bool, hasPassword: Bool)
        case unlocked
    }

    struct SyncStatus: Equatable {
        var enabled = false
        var last: Date?
        var error: String?
        var needsPassword = false
        var conflicts = 0
    }

    private(set) var state: State = .noVault
    private(set) var items: [ItemSummary] = []
    private(set) var sync = SyncStatus()
    /// Bumped on every change so open detail views reload.
    private(set) var revision = 0
    /// An `otpauth://` link iOS handed us (a setup QR code or link), waiting
    /// until the vault is open to become a new item.
    var pendingCodeSetup: CodeSetup?

    @ObservationIgnored private var session: VaultSession?
    /// The AutoFill extension turns this off: it fills from the local copy
    /// and leaves the (possibly slow) iCloud merge to the app.
    @ObservationIgnored var syncOnOpen = true

    init() { refreshState() }

    var isUnlocked: Bool { session != nil }

    func refreshState() {
        sync.enabled = Prefs.syncBookmark != nil
        if session != nil { state = .unlocked; return }
        guard let data = try? Data(contentsOf: AppGroup.vaultFile), let locked = try? LockedVault(bytes: data) else {
            state = .noVault
            return
        }
        state = .locked(
            quickUnlock: QuickUnlock.isEnabled && !Prefs.fullUnlockDue,
            hasPassword: locked.hasPasswordSlot()
        )
    }

    // MARK: Creating and joining

    /// Create a vault; returns the recovery code to show once.
    func create(password: String) async throws -> String {
        let device = Prefs.deviceId
        let nv = try await Task.detached { try createVault(password: password, device: device) }.value
        session = nv.session
        try writeLocal(try nv.session.toBytes())
        Prefs.lastFullUnlock = Date()
        afterOpen()
        return nv.recoveryCode
    }

    /// Join a vault kept in iCloud Drive or another Files location: copy it
    /// here and keep it merged from then on.
    func join(url: URL) throws {
        let bookmark = try withAccess(url) {
            _ = try LockedVault(bytes: try Data(contentsOf: url))
            try writeLocal(try Data(contentsOf: url))
            return try url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
        }
        Prefs.syncBookmark = bookmark
        refreshState()
    }

    // MARK: Unlocking

    func unlock(password: String) async throws {
        try await open(full: true) { try $0.unlockPassword(password: password, device: $1) }
    }

    func unlock(recoveryCode: String) async throws {
        try await open(full: true) { try $0.unlockRecovery(code: recoveryCode, device: $1) }
    }

    func unlockWithBiometrics() async throws {
        let (wrap, parked) = try await QuickUnlock.unwrap(reason: "Unlock Secret Vault")
        do {
            try await open(full: false) { try $0.resume(parked: parked, wrap: wrap, device: $1) }
        } catch let e as MobileError {
            // The key was rotated on another device, or the file was replaced.
            QuickUnlock.disable()
            refreshState()
            throw e
        }
    }

    private func open(full: Bool, _ unlock: @escaping @Sendable (LockedVault, UInt64) throws -> VaultSession) async throws {
        let device = Prefs.deviceId
        let s = try await Task.detached {
            let locked = try LockedVault(bytes: try Data(contentsOf: AppGroup.vaultFile))
            return try unlock(locked, device)
        }.value
        session = s
        if full { Prefs.lastFullUnlock = Date() }
        afterOpen()
        if syncOnOpen { await syncNow() }
    }

    private func afterOpen() {
        reloadItems()
        state = .unlocked
    }

    func enableQuickUnlock() throws {
        guard let s = session else { return }
        try QuickUnlock.enable { try s.park(wrap: $0) }
    }

    func lock() {
        session = nil
        items = []
        refreshState()
    }

    // MARK: Reading and editing

    private func reloadItems() {
        items = session?.items() ?? []
        revision += 1
        if Prefs.keyboardSuggestions { publishIdentities() }
    }

    func item(_ id: String) -> ItemDetail? { try? session?.item(id: id) }

    func totp(_ id: String) -> TotpCode? {
        guard let s = session else { return nil }
        return try? s.totp(id: id, now: UInt64(Date().timeIntervalSince1970))
    }

    func logins(for domain: String) -> [ItemSummary] { session?.loginsFor(page: domain) ?? [] }

    func slots() -> [SlotInfo] { session?.slots() ?? [] }

    /// The encrypted vault file as it stands, for saving a synced copy.
    func fileBytes() -> Data? { try? session?.toBytes() }

    @discardableResult
    func save(id: String?, edit: ItemEdit) throws -> String {
        guard let s = session else { throw MobileError.Invalid(message: "The vault is locked.") }
        mergeFolder(s, password: nil)
        let newId = try s.saveItem(id: id, edit: edit)
        try persist(s)
        return newId
    }

    /// Adds a one-time code to the login `to`, or to a new login.
    @discardableResult
    func addCode(_ input: String, title: String, account: String, to: String?) throws -> String {
        guard let s = session else { throw MobileError.Invalid(message: "The vault is locked.") }
        mergeFolder(s, password: nil)
        let id = try s.addCode(input: input, title: title, account: account, to: to)
        try persist(s)
        return id
    }

    func delete(id: String) throws {
        guard let s = session else { return }
        mergeFolder(s, password: nil)
        try s.deleteItem(id: id)
        try persist(s)
    }

    // MARK: Files

    private func persist(_ s: VaultSession) throws {
        let bytes = try s.toBytes()
        try writeLocal(bytes)
        if let url = syncURL() {
            do { try withAccess(url) { try coordinatedWrite(bytes, to: url) } }
            catch { sync.error = "Could not write the synced copy: \(describe(error))" }
        }
        reloadItems()
    }

    private func writeLocal(_ bytes: Data) throws {
        try bytes.write(to: AppGroup.vaultFile, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    // MARK: Sync

    private func syncURL() -> URL? {
        guard let b = Prefs.syncBookmark else { return nil }
        var stale = false
        guard let url = try? URL(resolvingBookmarkData: b, options: [], relativeTo: nil, bookmarkDataIsStale: &stale) else { return nil }
        if stale, let fresh = try? withAccess(url, { try url.bookmarkData() }) { Prefs.syncBookmark = fresh }
        return url
    }

    /// Use `url` (picked in Files) as the synced copy. `create` writes this
    /// vault there first; otherwise the file must be this vault.
    func setSync(url: URL?, create: Bool) async {
        guard let url else {
            Prefs.syncBookmark = nil
            sync = SyncStatus()
            return
        }
        do {
            let bookmark = try withAccess(url) {
                if create, let s = session { try coordinatedWrite(try s.toBytes(), to: url) }
                return try url.bookmarkData()
            }
            Prefs.syncBookmark = bookmark
            sync = SyncStatus(enabled: true)
            await syncNow()
        } catch {
            sync.error = describe(error)
        }
    }

    /// Merge the synced copy now. Pass the master password after a re-key.
    func syncNow(password: String? = nil) async {
        guard let s = session else { return }
        mergeFolder(s, password: password)
    }

    private func mergeFolder(_ s: VaultSession, password: String?) {
        guard let url = syncURL() else { return }
        do {
            try withAccess(url) {
                let theirs = try coordinatedRead(url)
                let r = try s.merge(bytes: theirs, password: password)
                if r.changed { try writeLocal(try s.toBytes()) }
                if r.changed || r.otherBehind { try coordinatedWrite(try s.toBytes(), to: url) }
                sync.last = Date()
                sync.error = nil
                sync.needsPassword = false
                sync.conflicts += Int(r.conflicts)
                if r.changed { reloadItems() }
            }
        } catch MobileError.Rekeyed(let m) {
            sync.error = m
            sync.needsPassword = true
        } catch MobileError.BadFile {
            sync.error = "The synced copy is incomplete; trying again later."
        } catch {
            sync.error = describe(error)
        }
    }

    private func withAccess<T>(_ url: URL, _ body: () throws -> T) throws -> T {
        let ok = url.startAccessingSecurityScopedResource()
        defer { if ok { url.stopAccessingSecurityScopedResource() } }
        return try body()
    }

    /// Reads through NSFileCoordinator so iCloud Drive downloads the latest
    /// version first.
    private func coordinatedRead(_ url: URL) throws -> Data {
        try? FileManager.default.startDownloadingUbiquitousItem(at: url)
        var result: Result<Data, Error> = .failure(CocoaError(.fileReadUnknown))
        var err: NSError?
        NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &err) { u in
            result = Result { try Data(contentsOf: u) }
        }
        if let err { throw err }
        return try result.get()
    }

    private func coordinatedWrite(_ data: Data, to url: URL) throws {
        var result: Result<Void, Error> = .success(())
        var err: NSError?
        NSFileCoordinator().coordinate(writingItemAt: url, options: .forReplacing, error: &err) { u in
            result = Result { try data.write(to: u, options: .atomic) }
        }
        if let err { throw err }
        try result.get()
    }

    // MARK: AutoFill suggestions

    /// Re-send the suggestions, e.g. after AutoFill was switched on in iOS
    /// Settings while the vault was open.
    func refreshSuggestions() {
        if Prefs.keyboardSuggestions { publishIdentities() }
    }

    /// Tell iOS which sites have logins so the QuickType bar can offer them.
    /// Usernames and sites only; passwords stay in the vault.
    private func publishIdentities() {
        guard let s = session else { return }
        var ids: [ASPasswordCredentialIdentity] = []
        for summary in items where summary.kind == .login {
            guard let detail = try? s.item(id: summary.id) else { continue }
            for u in detail.urls {
                guard let host = hostOf(url: u.url) else { continue }
                let service = ASCredentialServiceIdentifier(identifier: host, type: .domain)
                ids.append(ASPasswordCredentialIdentity(serviceIdentifier: service, user: detail.username, recordIdentifier: summary.id))
            }
        }
        ASCredentialIdentityStore.shared.getState { state in
            guard state.isEnabled else { return }
            ASCredentialIdentityStore.shared.replaceCredentialIdentities(ids) { _, _ in }
        }
    }

    // MARK: Reset

    /// Remove the vault from this device (the synced copy is left alone).
    func removeFromDevice() {
        lock()
        QuickUnlock.disable()
        try? FileManager.default.removeItem(at: AppGroup.vaultFile)
        Prefs.syncBookmark = nil
        ASCredentialIdentityStore.shared.removeAllCredentialIdentities { _, _ in }
        refreshState()
    }
}
