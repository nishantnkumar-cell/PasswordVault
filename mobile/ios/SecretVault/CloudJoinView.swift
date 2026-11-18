import SwiftUI
import VisionKit

/// Join cloud sync with the one-time link a computer shows (its Sync page,
/// Add a Device, or `vault cloud link`): paste it or scan its QR code.
/// With no vault here yet the vault is downloaded and then opens with the
/// master password; with a vault open, the two are merged.
struct CloudJoinView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(\.dismiss) private var dismiss
    @State private var link = ""
    @State private var scanning = false
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack {
                        TextField("Join link", text: $link, axis: .vertical)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .lineLimit(1...4)
                        if DataScannerViewController.isSupported {
                            Button { scanning = true } label: { Image(systemName: "qrcode.viewfinder") }
                                .buttonStyle(.borderless)
                                .accessibilityLabel("Scan QR code")
                        }
                    }
                } footer: {
                    Text("On your computer, open Secret Vault's Sync page and click Add a Device (or run vault cloud link). Scan the QR code it shows, or paste the link. A link works once, for 10 minutes.")
                }
                Section {
                    Button(action: join) {
                        HStack {
                            Text(vault.isUnlocked ? "Turn On Cloud Sync" : "Join")
                            if busy { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(busy || link.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                } footer: {
                    if !vault.isUnlocked {
                        Text("The vault is then downloaded to this device. Open it with your master password.")
                    }
                }
                if let error { Section { Text(error).foregroundStyle(.red) } }
            }
            .navigationTitle("Cloud Sync")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            .sheet(isPresented: $scanning) {
                QRScanner { code in
                    scanning = false
                    link = code
                    join()
                }
                .ignoresSafeArea()
            }
        }
    }

    private func join() {
        let l = link.trimmingCharacters(in: .whitespacesAndNewlines)
        busy = true
        error = nil
        Task {
            do {
                if vault.isUnlocked { try await vault.addCloud(link: l) } else { try await vault.joinCloud(link: l) }
                dismiss()
            } catch {
                self.error = describe(error)
            }
            busy = false
        }
    }
}
