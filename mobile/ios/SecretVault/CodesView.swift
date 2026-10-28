import SwiftUI
import VisionKit

/// Every one-time code in one place, like an authenticator app. Tap a tile to
/// copy its code. The grid adds columns as the window widens, so an iPad or
/// an unfolded foldable shows several at once.
struct CodesView: View {
    @Environment(VaultModel.self) private var vault
    @State private var query = ""
    @State private var copied: String?
    @State private var adding = false

    private var shown: [ItemSummary] {
        vault.items.filter { $0.hasTotp && $0.matches(query) }
    }

    var body: some View {
        ScrollView {
            TimelineView(.periodic(from: .now, by: 1)) { _ in
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 300), spacing: 14)], spacing: 14) {
                    ForEach(shown) { item in
                        if let code = vault.totp(item.id) {
                            CodeTile(item: item, code: code) {
                                SecureClipboard.copy(code.code, sensitive: true)
                                copied = "Code for \(item.title) copied."
                                Task {
                                    try? await Task.sleep(for: .seconds(2))
                                    copied = nil
                                }
                            }
                        }
                    }
                }
                .padding()
            }
        }
        .background(Palette.ground)
        .navigationTitle("One-Time Codes")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button { adding = true } label: { Label("Add Code", systemImage: "plus") }
            }
        }
        .sheet(isPresented: $adding) {
            NavigationStack { AddCodeView { adding = false } }
        }
        .searchable(text: $query, prompt: "Search codes")
        .overlay {
            if shown.isEmpty {
                ContentUnavailableView {
                    Label(query.isEmpty ? "No One-Time Codes" : "No Matches", systemImage: "clock.badge.checkmark")
                } description: {
                    Text(query.isEmpty ? "Tap + to scan a site's QR code or paste its setup key." : "Try another name.")
                } actions: {
                    if query.isEmpty {
                        Button("Add Code") { adding = true }.buttonStyle(.glassProminent)
                    }
                }
            }
        }
        .overlay(alignment: .bottom) {
            if let copied {
                Text(copied)
                    .font(.subheadline.weight(.medium))
                    .padding(.horizontal, 18).padding(.vertical, 12)
                    .glassEffect(.regular, in: .capsule)
                    .padding(.bottom, 24)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.snappy, value: copied)
        .refreshable { await vault.syncNow() }
    }
}

private struct CodeTile: View {
    let item: ItemSummary
    let code: TotpCode
    let copy: () -> Void

    var body: some View {
        Button(action: copy) {
            HStack(spacing: 14) {
                LetterTile(title: item.title, size: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.title).font(.subheadline.weight(.medium)).lineLimit(2)
                    Text(groupCode(code.code))
                        .font(.system(size: 30, weight: .semibold, design: .monospaced))
                        .foregroundStyle(code.remaining <= 5 ? Palette.warn : Palette.accent)
                        .contentTransition(.numericText())
                }
                Spacer(minLength: 0)
                TotpRing(remaining: Int(code.remaining), period: Int(code.period), size: 34)
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Palette.card, in: .rect(cornerRadius: 22, style: .continuous))
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(item.title), code \(code.code), \(code.remaining) seconds left")
        .accessibilityHint("Copies the code")
    }
}

/// Adds a one-time code straight from the Codes tab: scan the site's QR code
/// or paste its setup key, then keep it on a new login or on an existing one.
struct AddCodeView: View {
    @Environment(VaultModel.self) private var vault
    let onDone: () -> Void

    @State private var input = ""
    @State private var title = ""
    @State private var account = ""
    @State private var target: String?
    @State private var scanning = false
    @State private var error: String?

    /// Logins and notes that don't have a code yet.
    private var candidates: [ItemSummary] {
        vault.items.filter { ($0.kind == .login || $0.kind == .note) && !$0.hasTotp && !$0.hasKey }
            .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
    }

    private var preview: TotpCode? {
        input.isEmpty ? nil : try? previewTotp(input: input, now: UInt64(Date().timeIntervalSince1970))
    }

    var body: some View {
        Form {
            Section {
                if DataScannerViewController.isSupported {
                    Button { scanning = true } label: { Label("Scan QR Code", systemImage: "qrcode.viewfinder") }
                }
                TextField("Setup key or otpauth:// link", text: $input)
                    .font(.system(.body, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                if let code = preview {
                    Label("Current code: \(groupCode(code.code))", systemImage: "checkmark.circle").foregroundStyle(Palette.ok)
                } else if !input.isEmpty {
                    Label("This isn't a key the vault understands yet.", systemImage: "exclamationmark.triangle").foregroundStyle(Palette.warn)
                }
            } header: {
                Text("Code")
            } footer: {
                Text("When a site turns on two-factor sign-in it shows a QR code for an authenticator app. Scan it, or tap \"Can't scan?\" on the site and paste the key it shows.")
            }
            Section {
                Picker("Save To", selection: $target) {
                    Text("A new login").tag(String?.none)
                    ForEach(candidates) { item in
                        Text(item.title).tag(String?.some(item.id))
                    }
                }
                if target == nil {
                    TextField("Name, e.g. Example Mail", text: $title)
                    TextField("Account, e.g. alex@example.com", text: $account)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
            } footer: {
                Text("Keep the code on the login for the same site, so AutoFill can offer the code right after the password.")
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Add Code")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(role: .cancel) { onDone() } label: { Label("Cancel", systemImage: "xmark") }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(role: .confirm, action: save) { Label("Save", systemImage: "checkmark") }
                    .disabled(preview == nil)
            }
        }
        .sheet(isPresented: $scanning) {
            QRScanner { code in
                input = code
                scanning = false
            }
            .ignoresSafeArea()
        }
        .onChange(of: input) { fillNames() }
    }

    /// Takes the name and account from an otpauth:// link, and picks the
    /// login for the same site when there is exactly one.
    private func fillNames() {
        guard let label = codeLabel(input: input) else { return }
        if title.isEmpty { title = label.issuer }
        if account.isEmpty { account = label.account }
        let name = label.issuer.lowercased()
        let same = candidates.filter { !name.isEmpty && ($0.title.lowercased().contains(name) || ($0.host?.contains(name) ?? false)) }
        if target == nil, same.count == 1 { target = same[0].id }
    }

    private func save() {
        do {
            try vault.addCode(input, title: title, account: account, to: target)
            onDone()
        } catch {
            self.error = describe(error)
        }
    }
}
