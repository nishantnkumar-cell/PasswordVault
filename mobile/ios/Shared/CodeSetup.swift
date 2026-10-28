import Foundation

/// A one-time code set up from an `otpauth://` link, as in
/// `otpauth://totp/Example:alex@example.com?secret=...&issuer=Example`.
struct CodeSetup: Identifiable, Equatable {
    let id = UUID()
    /// The link itself; the vault parses the secret and settings from it.
    let uri: String
    let issuer: String
    let account: String

    /// Accepts `otpauth://` and Apple's `apple-otpauth://` spelling.
    init?(url: URL) {
        guard let scheme = url.scheme?.lowercased(), scheme == "otpauth" || scheme == "apple-otpauth",
              var parts = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        parts.scheme = "otpauth"
        guard let uri = parts.string else { return nil }
        // The label is "Issuer:account" or just "account".
        let label = (parts.path.removingPercentEncoding ?? parts.path).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let pieces = label.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        let named = parts.queryItems?.first { $0.name.lowercased() == "issuer" }?.value
        self.uri = uri
        self.issuer = named ?? (pieces.count == 2 ? pieces[0] : "")
        self.account = pieces.last ?? ""
    }
}
