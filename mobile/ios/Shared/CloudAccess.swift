import Foundation
import Security

/// This device's cloud sync access (docs/cloud-sync.md, "Phones"): the text
/// `cloudJoin` returned, with the device token in it, so it lives in the
/// Keychain (shared with the AutoFill extension), never in preferences.
/// The server version last seen and whether this device has changes the
/// server lacks are not secret and live in the App Group's preferences.
enum CloudAccess {
    private static let service = "dev.passwordvault.cloud-sync"
    private static let account = "device-access-v1"

    private static func baseQuery() -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let g = QuickUnlock.accessGroup { q[kSecAttrAccessGroup as String] = g }
        return q
    }

    /// The stored access, or nil when cloud sync is off on this device.
    static var access: String? {
        var q = baseQuery()
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }

    static var isOn: Bool { access != nil }

    static func save(_ text: String) throws {
        SecItemDelete(baseQuery() as CFDictionary)
        var add = baseQuery()
        add[kSecValueData as String] = Data(text.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw MobileError.Invalid(message: "Could not keep the cloud sync access in the Keychain (error \(status)).")
        }
    }

    static func clear() {
        SecItemDelete(baseQuery() as CFDictionary)
        version = nil
        dirty = false
        server = nil
    }

    private static var d: UserDefaults { AppGroup.defaults }

    /// The server's version after the last sync.
    static var version: UInt64? {
        get { (d.object(forKey: "cloudVersion") as? NSNumber)?.uint64Value }
        set { d.set(newValue.map { NSNumber(value: $0) }, forKey: "cloudVersion") }
    }

    /// This device saved something the server does not have yet.
    static var dirty: Bool {
        get { d.bool(forKey: "cloudDirty") }
        set { d.set(newValue, forKey: "cloudDirty") }
    }

    /// The server's address, to show.
    static var server: String? {
        get { d.string(forKey: "cloudServer") }
        set { d.set(newValue, forKey: "cloudServer") }
    }
}
