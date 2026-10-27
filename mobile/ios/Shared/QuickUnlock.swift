import Foundation
import LocalAuthentication
import Security

/// Face ID and Touch ID unlock (docs/mobile.md, "Quick unlock").
///
/// After a full unlock the vault key is parked under 32 random bytes
/// (`VaultSession.park`). The parked key is a file in the App Group; the 32
/// bytes are a Keychain item that only this device's current Face ID or
/// Touch ID enrolment can read (the Secure Enclave enforces the access
/// control), shared with the AutoFill extension through a keychain group.
enum QuickUnlock {
    private static let service = "dev.passwordvault.quick-unlock"
    private static let account = "wrap-key-v1"

    static var accessGroup: String? {
        // "<TeamID>.dev.passwordvault.shared"; nil in unsigned builds.
        guard let prefix = Bundle.main.object(forInfoDictionaryKey: "AppIdentifierPrefix") as? String else { return nil }
        return prefix + "dev.passwordvault.shared"
    }

    static var biometryName: String {
        let ctx = LAContext()
        _ = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch ctx.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default: return "Face ID"
        }
    }

    static var hardwareReady: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    static var isEnabled: Bool { FileManager.default.fileExists(atPath: AppGroup.parkedFile.path) }

    private static func baseQuery() -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let g = accessGroup { q[kSecAttrAccessGroup as String] = g }
        return q
    }

    static func disable() {
        SecItemDelete(baseQuery() as CFDictionary)
        try? FileManager.default.removeItem(at: AppGroup.parkedFile)
    }

    /// Turn on quick unlock; `park` wraps the open vault's key under the bytes.
    static func enable(park: (Data) throws -> Data) throws {
        guard hardwareReady else {
            throw QuickUnlockError.unavailable("Set up \(biometryName) in Settings first.")
        }
        disable()
        var wrap = Data(count: 32)
        let ok = wrap.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard ok == errSecSuccess else { throw QuickUnlockError.unavailable("No random numbers available.") }
        defer { wrap.resetBytes(in: 0..<wrap.count) }
        let parked = try park(wrap)
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error
        ) else {
            throw QuickUnlockError.unavailable("Could not protect the key: \(error!.takeRetainedValue())")
        }
        var add = baseQuery()
        add[kSecValueData as String] = wrap
        add[kSecAttrAccessControl as String] = access
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw QuickUnlockError.unavailable("Could not save the key (\(status)).")
        }
        try parked.write(to: AppGroup.parkedFile, options: [.atomic, .completeFileProtection])
    }

    /// Ask for Face ID or Touch ID; returns (wrap key, parked key).
    static func unwrap(reason: String) async throws -> (Data, Data) {
        guard let parked = try? Data(contentsOf: AppGroup.parkedFile) else {
            throw QuickUnlockError.unavailable("Quick unlock is off.")
        }
        let ctx = LAContext()
        ctx.localizedFallbackTitle = "Use Master Password"
        do {
            try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch let e as LAError where [.userCancel, .userFallback, .systemCancel, .appCancel].contains(e.code) {
            throw QuickUnlockError.cancelled
        }
        var q = baseQuery()
        q[kSecReturnData as String] = true
        q[kSecUseAuthenticationContext as String] = ctx
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        guard status == errSecSuccess, let wrap = out as? Data else {
            // A new face or fingerprint invalidates the item (.biometryCurrentSet).
            disable()
            throw QuickUnlockError.unavailable("\(biometryName) changed, so quick unlock was turned off. Unlock with your master password.")
        }
        return (wrap, parked)
    }
}

enum QuickUnlockError: LocalizedError {
    case unavailable(String)
    case cancelled

    var errorDescription: String? {
        switch self {
        case .unavailable(let m): return m
        case .cancelled: return nil
        }
    }
}
