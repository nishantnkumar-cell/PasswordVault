import AuthenticationServices
import SwiftUI
import UniformTypeIdentifiers

extension UTType {
    /// Secret Vault's encrypted file. Declared loosely, so Files shows any file.
    static let svault = UTType(filenameExtension: "svault", conformingTo: .data) ?? .data
}

/// The vault file handed to Files when making a new synced copy.
struct VaultDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.svault] }
    let data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

struct SettingsView: View {
    @Environment(VaultModel.self) private var vault
    @State private var quickUnlock = QuickUnlock.isEnabled
    @State private var autoLock = Prefs.autoLockSeconds
    @State private var clipboard = Prefs.clipboardSeconds
    @State private var suggestions = Prefs.keyboardSuggestions
    @State private var picking = false
    @State private var exporting = false
    @State private var exportDoc: VaultDocument?
    @State private var askPassword = false
    @State private var password = ""
    @State private var confirmRemove = false
    @State private var error: String?

    var body: some View {
        Form {
            unlockSection
            syncSection
            autofillSection
            Section("Unlock Methods on This Vault") {
                ForEach(vault.slots(), id: \.id) { slot in
                    HStack {
                        Image(systemName: slot.usableHere ? "checkmark.circle.fill" : "laptopcomputer")
                            .foregroundStyle(slot.usableHere ? Palette.ok : Palette.muted)
                        VStack(alignment: .leading) {
                            Text(slot.label)
                            Text(slot.usableHere ? slot.factor : "\(slot.factor), on another device").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Section {
                Button { vault.lock() } label: { Label("Lock Now", systemImage: "lock") }
                Button(role: .destructive) { confirmRemove = true } label: { Label("Remove Vault from This Device", systemImage: "trash") }
            } footer: {
                Text("Secret Vault \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "")")
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("Settings")
        .fileImporter(isPresented: $picking, allowedContentTypes: [.svault, .data]) { result in
            guard let url = try? result.get() else { return }
            Task { await vault.setSync(url: url, create: false) }
        }
        .fileExporter(isPresented: $exporting, document: exportDoc, contentType: .svault, defaultFilename: "vault.svault") { result in
            guard let url = try? result.get() else { return }
            Task { await vault.setSync(url: url, create: false) }
        }
        .alert("Merge the Re-keyed Copy", isPresented: $askPassword) {
            SecureField("Master password", text: $password)
            Button("Merge") {
                let p = password
                password = ""
                Task { await vault.syncNow(password: p) }
            }
            Button("Cancel", role: .cancel) { password = "" }
        } message: {
            Text("An unlock method was revoked on another device. Enter your master password to take the new key.")
        }
        .confirmationDialog("Remove the vault from this device?", isPresented: $confirmRemove, titleVisibility: .visible) {
            Button("Remove", role: .destructive) { vault.removeFromDevice() }
        } message: {
            Text("Items that were never synced are lost. Your computer and the synced copy are not changed.")
        }
    }

    @ViewBuilder private var unlockSection: some View {
        Section {
            if QuickUnlock.hardwareReady {
                Toggle("Unlock with \(QuickUnlock.biometryName)", isOn: $quickUnlock)
                    .onChange(of: quickUnlock) { _, on in
                        do {
                            if on { try vault.enableQuickUnlock() } else { QuickUnlock.disable() }
                        } catch {
                            self.error = describe(error)
                            quickUnlock = false
                        }
                    }
            }
            Picker("Lock After", selection: $autoLock) {
                Text("Immediately").tag(0)
                Text("1 minute").tag(60)
                Text("5 minutes").tag(300)
                Text("15 minutes").tag(900)
                Text("1 hour").tag(3600)
            }
            .onChange(of: autoLock) { _, v in Prefs.autoLockSeconds = v }
            Picker("Clear Clipboard After", selection: $clipboard) {
                Text("30 seconds").tag(30)
                Text("1 minute").tag(60)
                Text("2 minutes").tag(120)
                Text("5 minutes").tag(300)
            }
            .onChange(of: clipboard) { _, v in Prefs.clipboardSeconds = v }
        } header: {
            Text("Unlocking")
        } footer: {
            Text(QuickUnlock.hardwareReady
                 ? "\(QuickUnlock.biometryName) opens the vault with a key kept in this device's Secure Enclave. Every 14 days, and whenever someone adds a face or fingerprint, the master password is needed again."
                 : "Set up Face ID or Touch ID in the Settings app to unlock without typing your master password.")
        }
    }

    @ViewBuilder private var syncSection: some View {
        Section {
            if vault.sync.enabled {
                LabeledContent("Status") {
                    if let e = vault.sync.error {
                        Text(e).foregroundStyle(Palette.warn)
                    } else if let last = vault.sync.last {
                        Text("Synced \(last, format: .relative(presentation: .named))")
                    } else {
                        Text("Waiting")
                    }
                }
                if vault.sync.conflicts > 0 {
                    Text("\(vault.sync.conflicts) item(s) were edited on two devices at once. Both versions were kept; look for titles ending in \"(conflict)\".")
                        .font(.footnote).foregroundStyle(Palette.warn)
                }
                if vault.sync.needsPassword {
                    Button("Enter Master Password to Merge") { askPassword = true }
                }
                Button { Task { await vault.syncNow() } } label: { Label("Sync Now", systemImage: "arrow.triangle.2.circlepath") }
                Button("Stop Syncing", role: .destructive) { Task { await vault.setSync(url: nil, create: false) } }
            } else {
                Button { picking = true } label: { Label("Use My Computer's Synced File", systemImage: "folder") }
                Button {
                    exportDoc = vault.fileBytes().map(VaultDocument.init)
                    exporting = exportDoc != nil
                } label: {
                    Label("Save a Synced Copy to iCloud Drive", systemImage: "icloud.and.arrow.up")
                }
            }
        } header: {
            Text("Sync")
        } footer: {
            Text("Secret Vault keeps one encrypted file in a folder you choose (iCloud Drive, OneDrive, Dropbox) and merges changes from every device. The folder's provider only ever sees encrypted data.")
        }
    }

    @ViewBuilder private var autofillSection: some View {
        Section {
            Button {
                ASSettingsHelper.openCredentialProviderAppSettings { _ in }
            } label: {
                Label("Turn On AutoFill", systemImage: "key.viewfinder")
            }
            Toggle("Suggest Logins Above the Keyboard", isOn: $suggestions)
                .onChange(of: suggestions) { _, on in
                    Prefs.keyboardSuggestions = on
                    if !on { ASCredentialIdentityStore.shared.removeAllCredentialIdentities { _, _ in } }
                }
        } header: {
            Text("AutoFill")
        } footer: {
            Text("In Settings, open General › AutoFill & Passwords and switch on Secret Vault. Suggestions share only usernames and site names with iOS; passwords stay in the vault until you pick one with \(QuickUnlock.hardwareReady ? QuickUnlock.biometryName : "your passcode").")
        }
    }
}
