import Foundation

/// Storage shared by the app and its AutoFill extension through the App Group.
enum AppGroup {
    static let id = "group.dev.passwordvault.app"

    /// The App Group container, or the app's own Application Support folder
    /// when the group is unavailable (unsigned simulator builds).
    static var container: URL {
        if let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: id) {
            return url
        }
        let url = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    static var vaultFile: URL { container.appendingPathComponent("vault.svault") }
    static var parkedFile: URL { container.appendingPathComponent("quick-unlock.bin") }

    static var defaults: UserDefaults { UserDefaults(suiteName: id) ?? .standard }
}

/// App preferences. Nothing here is secret.
enum Prefs {
    private static var d: UserDefaults { AppGroup.defaults }

    /// This device's ID in each item's version vector (docs/sync.md).
    static var deviceId: UInt64 {
        if let n = d.object(forKey: "deviceId") as? NSNumber, n.uint64Value != 0 { return n.uint64Value }
        var id: UInt64 = 0
        while id == 0 { id = UInt64.random(in: 1...UInt64.max) }
        d.set(NSNumber(value: id), forKey: "deviceId")
        return id
    }

    /// Lock after this many seconds in the background; 0 locks at once.
    static var autoLockSeconds: Int {
        get { d.object(forKey: "autoLock") as? Int ?? 300 }
        set { d.set(newValue, forKey: "autoLock") }
    }

    /// Clear copied secrets from the clipboard after this long.
    static var clipboardSeconds: Int {
        get { d.object(forKey: "clipboard") as? Int ?? 60 }
        set { d.set(newValue, forKey: "clipboard") }
    }

    /// When the vault was last opened with the master password or recovery code.
    static var lastFullUnlock: Date {
        get { d.object(forKey: "fullUnlock") as? Date ?? .distantPast }
        set { d.set(newValue, forKey: "fullUnlock") }
    }

    /// Bookmark to the synced copy in iCloud Drive or another Files provider.
    static var syncBookmark: Data? {
        get { d.data(forKey: "syncBookmark") }
        set { d.set(newValue, forKey: "syncBookmark") }
    }

    /// Offer logins in the QuickType bar (usernames and sites go to iOS's
    /// credential identity store; passwords never do).
    static var keyboardSuggestions: Bool {
        get { d.object(forKey: "suggestions") as? Bool ?? true }
        set { d.set(newValue, forKey: "suggestions") }
    }

    /// Quick unlock needs the master password again after this long.
    static let fullUnlockEvery: TimeInterval = 14 * 24 * 60 * 60
    static var fullUnlockDue: Bool { Date().timeIntervalSince(lastFullUnlock) > fullUnlockEvery }
}

extension MobileError {
    /// The sentence Rust wrote for this error, ready to show.
    var message: String {
        switch self {
        case let .WrongCredential(m), let .BadFile(m), let .DifferentVault(m),
             let .Rekeyed(m), let .NotFound(m), let .Invalid(m):
            return m
        }
    }
}

/// A user-facing sentence for any error.
func describe(_ error: Error) -> String {
    if let e = error as? MobileError { return e.message }
    if let e = error as? LocalizedError, let d = e.errorDescription { return d }
    return error.localizedDescription
}
