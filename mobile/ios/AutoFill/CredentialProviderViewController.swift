import AuthenticationServices
import SwiftUI

/// The AutoFill sheet iOS shows over Safari and other apps.
///
/// It unlocks only with Face ID or Touch ID: a master-password unlock runs
/// Argon2 with 256 MiB, more memory than iOS lets an AutoFill extension use.
/// When quick unlock is off (or the 14-day password check is due) it asks
/// the user to open the app once instead.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let vault: VaultModel = {
        let v = VaultModel()
        v.syncOnOpen = false
        return v
    }()

    private func show(_ mode: AutoFillMode) {
        let root = AutoFillView(mode: mode, finish: { [weak self] in self?.finish($0) })
            .environment(vault)
            .tint(Palette.accent)
        let host = UIHostingController(rootView: root)
        children.forEach { $0.willMove(toParent: nil); $0.view.removeFromSuperview(); $0.removeFromParent() }
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    private func finish(_ result: AutoFillResult) {
        switch result {
        case let .password(user, password):
            extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: user, password: password))
        case let .code(code):
            extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code))
        case .cancel:
            extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
        }
    }

    // MARK: Requests from iOS

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(.passwords(pages: serviceIdentifiers.map(\.identifier)))
    }

    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(.codes(pages: serviceIdentifiers.map(\.identifier)))
    }

    /// A suggestion from the QuickType bar. The vault is always locked here,
    /// so ask iOS to show our interface, which unlocks with Face ID.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userInteractionRequired.rawValue))
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        guard let id = credentialRequest.credentialIdentity.recordIdentifier else {
            finish(.cancel)
            return
        }
        show(credentialRequest.type == .oneTimeCode ? .recordCode(id) : .record(id))
    }
}

enum AutoFillMode {
    /// Pick a login for these pages (URLs or domains iOS reported).
    case passwords(pages: [String])
    /// Pick a one-time code for these pages.
    case codes(pages: [String])
    /// Fill this login, picked from the QuickType bar.
    case record(String)
    case recordCode(String)
}

enum AutoFillResult {
    case password(user: String, password: String)
    case code(String)
    case cancel
}

struct AutoFillView: View {
    @Environment(VaultModel.self) private var vault
    let mode: AutoFillMode
    let finish: (AutoFillResult) -> Void
    @State private var query = ""
    @State private var error: String?
    @State private var mismatch: ItemSummary?

    private var pages: [String] {
        switch mode {
        case let .passwords(p), let .codes(p): return p
        default: return []
        }
    }

    private var wantsCode: Bool {
        switch mode {
        case .codes, .recordCode: return true
        default: return false
        }
    }

    private var site: String? { pages.lazy.compactMap { hostOf(url: $0) }.first }

    var body: some View {
        NavigationStack {
            Group {
                if vault.isUnlocked { picker } else { locked }
            }
            .navigationTitle(site ?? "Secret Vault")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(role: .cancel) { finish(.cancel) } label: { Label("Cancel", systemImage: "xmark") }
                }
            }
        }
        .task { await unlock() }
    }

    // MARK: Locked

    private var locked: some View {
        VStack(spacing: 18) {
            Spacer()
            AppIconView(size: 72)
            if case .locked(true, _) = vault.state {
                Button { Task { await unlock() } } label: {
                    Label("Unlock with \(QuickUnlock.biometryName)", systemImage: QuickUnlock.biometryName == "Touch ID" ? "touchid" : "faceid")
                        .font(.headline)
                        .padding(.horizontal, 8)
                }
                .buttonStyle(.glassProminent)
                .controlSize(.large)
            } else {
                Text(lockedHelp)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(Palette.muted)
                    .padding(.horizontal, 32)
            }
            if let error {
                Text(error).foregroundStyle(.red).multilineTextAlignment(.center).padding(.horizontal, 32)
            }
            Spacer()
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .background(UnlockWash())
    }

    private var lockedHelp: String {
        switch vault.state {
        case .noVault:
            return "Open Secret Vault and create or add your vault first."
        case .locked where QuickUnlock.isEnabled:
            return "It's been 14 days since you last typed your master password. Open Secret Vault and unlock it once, then AutoFill works with \(QuickUnlock.biometryName) again."
        default:
            return "AutoFill unlocks with Face ID or Touch ID. Open Secret Vault, unlock it, and turn on \(QuickUnlock.biometryName) in Settings."
        }
    }

    private func unlock() async {
        guard !vault.isUnlocked, case .locked(true, _) = vault.state else { return }
        do {
            try await vault.unlockWithBiometrics()
            error = nil
            fillRecordIfAsked()
        } catch QuickUnlockError.cancelled {
        } catch {
            self.error = describe(error)
        }
    }

    /// QuickType suggestions name one item: fill it without showing the list.
    private func fillRecordIfAsked() {
        switch mode {
        case let .record(id):
            if let item = vault.item(id) { finish(.password(user: item.username, password: item.password)) } else { finish(.cancel) }
        case let .recordCode(id):
            if let code = vault.totp(id) { finish(.code(code.code)) } else { finish(.cancel) }
        default:
            break
        }
    }

    // MARK: Picking

    /// Logins saved for the page; one-time-code requests also need a code.
    private var matching: [ItemSummary] {
        var seen = Set<String>()
        return pages.flatMap { vault.logins(for: $0) }
            .filter { seen.insert($0.id).inserted && (!wantsCode || $0.hasTotp) }
    }

    private var others: [ItemSummary] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return [] }
        let ids = Set(matching.map(\.id))
        return vault.items.filter {
            $0.kind == .login && !ids.contains($0.id) && (!wantsCode || $0.hasTotp)
                && ($0.title.lowercased().contains(q) || $0.subtitle.lowercased().contains(q) || ($0.host?.contains(q) ?? false))
        }
    }

    private var picker: some View {
        List {
            Section {
                if matching.isEmpty {
                    Text(site.map { "No logins are saved for \($0). Search to pick another one." } ?? "Search for the login to fill.")
                        .foregroundStyle(.secondary)
                }
                ForEach(matching) { item in
                    Button { pick(item) } label: { ItemLine(item: item) }
                }
            } header: {
                if !matching.isEmpty { Text(site.map { "Saved for \($0)" } ?? "Suggested") }
            }
            if !others.isEmpty {
                Section("Other Logins") {
                    ForEach(others) { item in
                        Button { mismatch = item } label: { ItemLine(item: item) }
                    }
                }
            }
        }
        .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always), prompt: "Search all logins")
        .confirmationDialog(mismatchTitle, isPresented: Binding(get: { mismatch != nil }, set: { if !$0 { mismatch = nil } }), titleVisibility: .visible) {
            Button("Fill Anyway", role: .destructive) { if let m = mismatch { pick(m) } }
        } message: {
            Text("Phishing sites copy real ones. Only fill if you're sure this is the right place.")
        }
    }

    private var mismatchTitle: String {
        guard let m = mismatch else { return "" }
        return "\(m.title) is saved for \(m.host ?? "another site"), not \(site ?? "this app")."
    }

    private func pick(_ item: ItemSummary) {
        mismatch = nil
        if wantsCode {
            if let code = vault.totp(item.id) { finish(.code(code.code)) }
        } else if let detail = vault.item(item.id) {
            finish(.password(user: detail.username, password: detail.password))
        }
    }
}

private struct ItemLine: View {
    let item: ItemSummary

    var body: some View {
        HStack(spacing: 12) {
            LetterTile(title: item.title)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title).font(.body.weight(.medium)).foregroundStyle(.primary).lineLimit(2)
                Text(item.subtitle.isEmpty ? (item.host ?? "") : item.subtitle)
                    .font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
            }
        }
    }
}

private struct UnlockWash: View {
    var body: some View {
        RadialGradient(colors: [Palette.accent.opacity(0.16), Palette.ground], center: .top, startRadius: 0, endRadius: 420)
            .ignoresSafeArea()
    }
}
