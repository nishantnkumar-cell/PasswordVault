import SwiftUI

/// Settings › Unlock Methods: the vault's keyslots, and the changes a phone
/// can make to them. Security keys, TPMs and phone passkeys are added on a
/// computer, but can be removed here.
struct UnlockMethodsView: View {
    @Environment(VaultModel.self) private var vault
    @State private var changing = false
    @State private var confirmNewCode = false
    @State private var revoking = false
    @State private var removing: SlotInfo?
    @State private var busy = false
    @State private var newCode: NewCode?
    @State private var done: String?
    @State private var error: String?

    var body: some View {
        let _ = vault.revision
        let slots = vault.slots()
        let passwords = slots.filter { $0.factor == "password" }.count
        Form {
            Section {
                ForEach(slots, id: \.id) { slot in
                    SlotRow(slot: slot)
                        .swipeActions {
                            if slot.factor != "password" || passwords > 1 {
                                Button("Remove", role: .destructive) { removing = slot }
                            }
                        }
                        .contextMenu {
                            if slot.factor != "password" || passwords > 1 {
                                Button("Remove", systemImage: "trash", role: .destructive) { removing = slot }
                            }
                        }
                }
            } header: {
                Text("On This Vault")
            } footer: {
                Text("Swipe left on a method to remove it. Security keys, the TPM and phone passkeys are added in the desktop app; they unlock only on the computer that added them.")
            }

            Section {
                Button { changing = true } label: { Label("Change Master Password", systemImage: "character.cursor.ibeam") }
                Button { confirmNewCode = true } label: { Label("Make a New Recovery Code", systemImage: "key.card") }
            } footer: {
                Text("Changes reach your other devices at their next sync. Devices that use Face ID, Touch ID or Windows Hello keep working.")
            }

            Section {
                Button(role: .destructive) { revoking = true } label: {
                    Label("Remove All Other Unlock Methods", systemImage: "exclamationmark.shield")
                }
            } header: {
                Text("Lost a Device or Key?")
            } footer: {
                Text("Gives the vault a new key and keeps only your master password. Every security key, TPM, phone passkey, other password and recovery code stops working, and you get a new recovery code. Each other device asks for the master password once.")
            }

            if busy {
                Section { HStack { ProgressView(); Text("Working… this takes a few seconds.").foregroundStyle(.secondary) } }
            }
            if let done {
                Section { Label(done, systemImage: "checkmark.circle.fill").foregroundStyle(Palette.ok) }
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Unlock Methods")
        .disabled(busy)
        .sheet(isPresented: $changing) {
            NavigationStack { ChangePasswordView { changing = false; if $0 { done = "Master password changed." } } }
        }
        .sheet(isPresented: $revoking) {
            NavigationStack {
                RevokeOthersView { code in
                    revoking = false
                    if let code { newCode = NewCode(code: code, title: "Other Methods Removed") }
                }
            }
        }
        .sheet(item: $newCode) { c in
            NavigationStack { NewRecoveryCodeView(code: c.code, title: c.title) { newCode = nil } }
                .interactiveDismissDisabled()
        }
        .confirmationDialog("Make a new recovery code?", isPresented: $confirmNewCode, titleVisibility: .visible) {
            Button("Make New Code") { run { try await vault.newRecoveryCode() } }
        } message: {
            Text("Your current recovery code stops working. The new one is shown once.")
        }
        .confirmationDialog(removing.map { "Remove \(SlotRow.name($0))?" } ?? "", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }), titleVisibility: .visible) {
            Button("Remove", role: .destructive) {
                guard let slot = removing else { return }
                do {
                    try vault.removeSlot(slot.id)
                    done = "\(SlotRow.name(slot)) removed."
                    error = nil
                } catch { self.error = describe(error) }
            }
        } message: {
            Text("It stops unlocking this vault. If it might be in someone else's hands, use Remove All Other Unlock Methods instead: that also changes the vault's key.")
        }
    }

    private func run(_ body: @escaping () async throws -> String) {
        busy = true
        error = nil
        done = nil
        Task {
            do { newCode = NewCode(code: try await body(), title: "New Recovery Code") }
            catch { self.error = describe(error) }
            busy = false
        }
    }
}

private struct NewCode: Identifiable {
    let code: String
    let title: String
    var id: String { code }
}

struct SlotRow: View {
    let slot: SlotInfo

    /// A slot without its own name is labelled with its kind; don't say it twice.
    static func name(_ slot: SlotInfo) -> String {
        let kind = slot.factor.prefix(1).uppercased() + slot.factor.dropFirst()
        let named = !slot.label.isEmpty && slot.label.lowercased() != slot.factor.lowercased()
        return named ? slot.label : kind
    }

    var body: some View {
        let kind = slot.factor.prefix(1).uppercased() + slot.factor.dropFirst()
        let named = Self.name(slot) != kind
        HStack {
            Image(systemName: slot.usableHere ? "checkmark.circle.fill" : "laptopcomputer")
                .foregroundStyle(slot.usableHere ? Palette.ok : Palette.muted)
            VStack(alignment: .leading) {
                Text(Self.name(slot))
                Text((named ? "\(kind) · " : "") + (slot.usableHere ? "Works on this device" : "Works on the computer that added it"))
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

struct ChangePasswordView: View {
    @Environment(VaultModel.self) private var vault
    let onDone: (Bool) -> Void
    @State private var current = ""
    @State private var new = ""
    @State private var repeated = ""
    @State private var busy = false
    @State private var error: String?

    private var ready: Bool { !current.isEmpty && new.count >= 8 && new == repeated && !busy }

    var body: some View {
        Form {
            Section("Current Master Password") {
                SecureField("Current password", text: $current).textContentType(.password)
            }
            Section {
                SecureField("New password", text: $new).textContentType(.newPassword)
                SecureField("Type it again", text: $repeated).textContentType(.newPassword)
            } header: {
                Text("New Master Password")
            } footer: {
                if !repeated.isEmpty && new != repeated {
                    Text("The two new passwords are different.").foregroundStyle(Palette.warn)
                } else {
                    Text("Use at least 12 characters, or four random words (the Generator makes them). Your recovery code, security keys and other unlock methods keep working.")
                }
            }
            if busy { Section { HStack { ProgressView(); Text("Changing… this takes a few seconds.").foregroundStyle(.secondary) } } }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("Change Password")
        .navigationBarTitleDisplayMode(.inline)
        .disabled(busy)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { onDone(false) } }
            ToolbarItem(placement: .confirmationAction) { Button("Change", action: change).disabled(!ready) }
        }
    }

    private func change() {
        busy = true
        error = nil
        let (c, n) = (current, new)
        Task {
            do {
                try await vault.changePassword(current: c, new: n)
                onDone(true)
            } catch MobileError.WrongCredential {
                error = "That isn't the current master password."
            } catch {
                self.error = describe(error)
            }
            busy = false
        }
    }
}

struct RevokeOthersView: View {
    @Environment(VaultModel.self) private var vault
    let onDone: (String?) -> Void
    @State private var password = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                Label("Every security key, TPM and phone passkey", systemImage: "xmark.circle")
                Label("Every other master password", systemImage: "xmark.circle")
                Label("Your recovery code (you get a new one)", systemImage: "xmark.circle")
            } header: {
                Text("These Stop Working")
            }
            Section {
                Label("Your master password", systemImage: "checkmark.circle")
                Label("Face ID or Touch ID on this device", systemImage: "checkmark.circle")
                Label("Your items, on every device", systemImage: "checkmark.circle")
            } header: {
                Text("These Keep Working")
            } footer: {
                Text("Other phones and computers ask for the master password once, at their next sync. Add security keys or the TPM again in the desktop app afterwards.")
            }
            Section("Confirm With Your Master Password") {
                SecureField("Master password", text: $password).textContentType(.password)
            }
            if busy { Section { HStack { ProgressView(); Text("Changing the vault's key…").foregroundStyle(.secondary) } } }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("Remove Other Methods")
        .navigationBarTitleDisplayMode(.inline)
        .disabled(busy)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { onDone(nil) } }
            ToolbarItem(placement: .destructiveAction) {
                Button("Remove", role: .destructive, action: revoke).disabled(password.isEmpty || busy)
            }
        }
    }

    private func revoke() {
        busy = true
        error = nil
        let p = password
        Task {
            do {
                onDone(try await vault.revokeOthers(password: p))
            } catch MobileError.WrongCredential {
                error = "That isn't the master password."
            } catch {
                self.error = describe(error)
            }
            busy = false
        }
    }
}

/// A new recovery code, shown once, like the one at setup.
struct NewRecoveryCodeView: View {
    let code: String
    let title: String
    let onDone: () -> Void
    @State private var saved = false

    var body: some View {
        Form {
            Section {
                Text(code.split(separator: "-").chunked(2).joined(separator: "\n"))
                    .font(.system(.title3, design: .monospaced).weight(.semibold))
                    .multilineTextAlignment(.center)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                Button("Copy (cleared in \(Prefs.clipboardSeconds) s)") { SecureClipboard.copy(code, sensitive: true) }
            } header: {
                Text("Your New Recovery Code")
            } footer: {
                Text("Write it on paper and keep it somewhere safe, in place of the old one, which no longer works. It is shown only now.")
            }
            Section { Toggle("I wrote it down", isOn: $saved) }
        }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) { Button("Done", action: onDone).disabled(!saved) }
        }
    }
}
