import SwiftUI

/// The public half of an SSH or OpenPGP key item: what you give to GitHub,
/// a server or a correspondent. The private key stays in the vault.
struct KeyPublicSection: View {
    let key: KeyPublic
    let copy: (String, String, Bool) -> Void

    private var publicName: String { key.kind == "SSH" ? "Public key" : "Public certificate" }

    var body: some View {
        Section {
            LabeledContent("Type", value: "\(key.kind) · \(key.algorithm)")
            VStack(alignment: .leading, spacing: 2) {
                Text("Fingerprint").font(.subheadline).foregroundStyle(.secondary)
                Text(key.fingerprint).font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(publicName).font(.subheadline).foregroundStyle(.secondary)
                Text(key.publicText)
                    .font(.system(.caption, design: .monospaced))
                    .lineLimit(key.kind == "SSH" ? 4 : 8)
                    .textSelection(.enabled)
            }
            HStack {
                Button { copy(publicName, key.publicText, false) } label: {
                    Label(key.kind == "SSH" ? "Copy Public Key" : "Copy Certificate", systemImage: "doc.on.doc")
                }
                .buttonStyle(.glassProminent)
                Spacer()
                ShareLink(item: key.publicText, subject: Text(publicName)) {
                    Label("Share", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.glass)
            }
        } header: {
            Text(key.kind == "SSH" ? "SSH Key" : "OpenPGP Key")
        } footer: {
            Text(key.kind == "SSH"
                 ? "Paste the public key into GitHub (Settings › SSH and GPG keys) or a server's authorized_keys. The private key never leaves the vault; your computer's vault daemon signs with it\(key.confirm ? " after you approve each use" : "")."
                 : "Send the public certificate to people who write to you, or paste it into GitHub for signed commits. The secret key never leaves the vault; your computer's vault daemon uses it\(key.confirm ? " after you approve each use" : "").")
        }
    }
}

/// New Item › SSH Key.
struct NewSshKeyView: View {
    @Environment(VaultModel.self) private var vault
    let onDone: (String?) -> Void
    @State private var title = ""
    @State private var kind: SshKeyKind = .ed25519
    @State private var confirm = true
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                TextField("Name, such as GitHub or Home Server", text: $title)
                    .textInputAutocapitalization(.words)
            } footer: {
                Text("The name is also the key's comment, at the end of the public key.")
            }
            Section {
                Picker("Type", selection: $kind) {
                    Text("Ed25519 (recommended)").tag(SshKeyKind.ed25519)
                    Text("ECDSA P-256").tag(SshKeyKind.ecdsaP256)
                }
                Toggle("Ask Before Each Use", isOn: $confirm)
            } footer: {
                Text("Choose ECDSA only for an older server that refuses Ed25519. With Ask Before Each Use, your computer shows an approval window before each SSH login or Git signature.")
            }
            Section {
                Text("The key is made on this phone and saved in the vault. After the vault syncs, your computer's vault daemon offers it to ssh and git. Copy the public key from the item to add it to GitHub or a server.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("New SSH Key")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(role: .cancel) { onDone(nil) } label: { Label("Cancel", systemImage: "xmark") }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(role: .confirm) {
                    do { onDone(try vault.generateSshKey(title: title, kind: kind, confirm: confirm)) }
                    catch { self.error = describe(error) }
                } label: { Label("Make Key", systemImage: "checkmark") }
                .disabled(title.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }
}
