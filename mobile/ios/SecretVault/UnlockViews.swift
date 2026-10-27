import SwiftUI
import UniformTypeIdentifiers

/// The soft blue wash behind the unlock screens.
struct UnlockBackground: View {
    var body: some View {
        RadialGradient(colors: [Palette.accent.opacity(0.16), Palette.ground], center: .top, startRadius: 0, endRadius: 520)
            .background(Palette.ground)
            .ignoresSafeArea()
    }
}

/// Width-limited column, so phones, iPads and open foldables all look right.
struct CenteredColumn<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        ScrollView {
            VStack(spacing: 0) { content }
                .frame(maxWidth: 440)
                .padding(.horizontal, 24)
                .padding(.vertical, 40)
                .frame(maxWidth: .infinity)
        }
        .scrollBounceBehavior(.basedOnSize)
        .background(UnlockBackground())
    }
}

struct WelcomeView: View {
    @Environment(VaultModel.self) private var vault
    let onCreated: (String) -> Void
    @State private var creating = false
    @State private var password = ""
    @State private var confirm = ""
    @State private var busy = false
    @State private var error: String?
    @State private var picking = false

    var body: some View {
        CenteredColumn {
            AppIconView().padding(.top, 40)
            Text("Secret Vault").font(.largeTitle.bold()).padding(.top, 22)
            Text("Your passwords, cards and one-time codes, encrypted on this device. Nothing is sent to a server.")
                .multilineTextAlignment(.center).foregroundStyle(Palette.muted).padding(.top, 8)

            if !creating {
                VStack(spacing: 12) {
                    Button { creating = true } label: { Text("Create a New Vault").frame(maxWidth: .infinity) }
                        .buttonStyle(.glassProminent).controlSize(.large)
                    Button { picking = true } label: { Text("Use a Vault from My Computer").frame(maxWidth: .infinity) }
                        .buttonStyle(.glass).controlSize(.large)
                    Text("To use your desktop vault here, turn on Sync on your computer with a folder in iCloud Drive, OneDrive or Dropbox, then pick the synced .svault file.")
                        .font(.footnote).foregroundStyle(Palette.muted).multilineTextAlignment(.center)
                }
                .padding(.top, 36)
            } else {
                VStack(alignment: .leading, spacing: 12) {
                    // Captions stay once typing hides the placeholders, as on the unlock screen.
                    Text("Master password").font(.subheadline.weight(.semibold)).foregroundStyle(Palette.muted)
                    SecureField("Master password", text: $password)
                        .textContentType(.newPassword)
                        .padding(14).background(.background, in: .rect(cornerRadius: 14))
                    Text("Type it again").font(.subheadline.weight(.semibold)).foregroundStyle(Palette.muted)
                    SecureField("Type it again", text: $confirm)
                        .textContentType(.newPassword)
                        .padding(14).background(.background, in: .rect(cornerRadius: 14))
                    Text("Use at least 12 characters, or four random words. Nobody can recover this password for you; the recovery code on the next screen is the only other way in.")
                        .font(.footnote).foregroundStyle(Palette.muted)
                    Button {
                        guard password == confirm else { error = "The two passwords are different."; return }
                        busy = true
                        Task {
                            do { onCreated(try await vault.create(password: password)) } catch { self.error = describe(error) }
                            busy = false
                        }
                    } label: {
                        Group { if busy { ProgressView() } else { Text("Create Vault") } }.frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glassProminent).controlSize(.large)
                    .disabled(busy || password.count < 8)
                    Button("Back") { creating = false }.frame(maxWidth: .infinity)
                }
                .padding(.top, 28)
            }
            if let error { Text(error).foregroundStyle(.red).multilineTextAlignment(.center).padding(.top, 12) }
        }
        .fileImporter(isPresented: $picking, allowedContentTypes: [.data]) { result in
            do { try vault.join(url: try result.get()) } catch { self.error = describe(error) }
        }
    }
}

struct RecoveryCodeView: View {
    @Environment(VaultModel.self) private var vault
    let code: String
    let onDone: () -> Void
    @State private var saved = false

    var body: some View {
        CenteredColumn {
            Text("Your Recovery Code").font(.title.bold()).padding(.top, 24)
            Text("If you forget your master password, this code is the only way back in. Write it on paper and keep it somewhere safe. It is shown only now.")
                .multilineTextAlignment(.center).foregroundStyle(Palette.muted).padding(.top, 8)
            // Two groups to a line, so no group is split across lines.
            Text(code.split(separator: "-").chunked(2).joined(separator: "\n"))
                .font(.system(.title3, design: .monospaced).weight(.semibold))
                .multilineTextAlignment(.center)
                .textSelection(.enabled)
                .padding(24).frame(maxWidth: .infinity)
                .glassEffect(.regular.tint(Palette.accent.opacity(0.15)), in: .rect(cornerRadius: 24))
                .padding(.top, 24)
            Button("Copy (cleared in \(Prefs.clipboardSeconds) s)") { SecureClipboard.copy(code, sensitive: true) }
                .padding(.top, 8)
            Toggle("I wrote it down", isOn: $saved).padding(.top, 16)
            Button {
                if QuickUnlock.hardwareReady { try? vault.enableQuickUnlock() }
                onDone()
            } label: {
                Text(QuickUnlock.hardwareReady ? "Continue and Use \(QuickUnlock.biometryName)" : "Continue").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent).controlSize(.large).disabled(!saved).padding(.top, 20)
            if QuickUnlock.hardwareReady {
                Button("Continue Without \(QuickUnlock.biometryName)", action: onDone).disabled(!saved).padding(.top, 8)
            }
        }
    }
}

struct UnlockView: View {
    @Environment(VaultModel.self) private var vault
    let quickUnlock: Bool
    let hasPassword: Bool
    @State private var secret = ""
    @State private var recovery = false
    @State private var busy = false
    @State private var error: String?
    @FocusState private var focused: Bool

    var body: some View {
        CenteredColumn {
            AppIconView().padding(.top, 60)
            Text("Secret Vault").font(.title.bold()).padding(.top, 22)
            Text("Locked").foregroundStyle(Palette.muted).padding(.top, 2)

            if quickUnlock {
                Button(action: biometric) {
                    Image(systemName: QuickUnlock.biometryName == "Touch ID" ? "touchid" : "faceid")
                        .font(.system(size: 44, weight: .regular))
                        .frame(width: 96, height: 96)
                }
                .buttonStyle(.glass)
                .buttonBorderShape(.circle)
                .accessibilityLabel("Unlock with \(QuickUnlock.biometryName)")
                .padding(.top, 48)
                Text("Unlock with \(QuickUnlock.biometryName)").font(.headline).padding(.top, 12)
            } else if QuickUnlock.isEnabled && Prefs.fullUnlockDue {
                Text("It's been 14 days: enter your master password once to keep \(QuickUnlock.biometryName) on.")
                    .font(.footnote).foregroundStyle(Palette.muted).multilineTextAlignment(.center).padding(.top, 24)
            }

            VStack(alignment: .leading, spacing: 12) {
                Text(recovery ? "Recovery code" : "Master password").font(.subheadline.weight(.semibold)).foregroundStyle(Palette.muted)
                HStack(spacing: 10) {
                    SecureField(recovery ? "XXXX-XXXX-…" : "Password", text: $secret)
                        .textContentType(.password)
                        .focused($focused)
                        .submitLabel(.go)
                        .onSubmit(submit)
                        .padding(.horizontal, 14).frame(height: 48)
                        .background(.background, in: .rect(cornerRadius: 14))
                    Button(action: submit) {
                        if busy { ProgressView() } else { Text("Unlock").fontWeight(.semibold) }
                    }
                    .buttonStyle(.glassProminent).controlSize(.large)
                    .disabled(busy || secret.isEmpty)
                }
                Button(recovery ? "Use master password instead" : "Use recovery code instead") {
                    recovery.toggle(); secret = ""
                }
                .font(.subheadline).frame(maxWidth: .infinity)
                if !hasPassword && !recovery {
                    Text("This vault has no password-only unlock method, so use the recovery code here or add a password on your computer.")
                        .font(.footnote).foregroundStyle(Palette.muted)
                }
            }
            .padding(18)
            .glassEffect(.regular, in: .rect(cornerRadius: 26))
            .padding(.top, 40)

            if let error { Text(error).foregroundStyle(.red).multilineTextAlignment(.center).padding(.top, 12) }
        }
        .task { if quickUnlock { biometric() } }
    }

    private func biometric() {
        Task {
            do { try await vault.unlockWithBiometrics() } catch {
                if case QuickUnlockError.cancelled = error { focused = true } else { self.error = describe(error) }
            }
        }
    }

    private func submit() {
        guard !secret.isEmpty, !busy else { return }
        busy = true
        error = nil
        let s = secret
        Task {
            do {
                if recovery { try await vault.unlock(recoveryCode: s) } else { try await vault.unlock(password: s) }
                secret = ""
            } catch { self.error = describe(error) }
            busy = false
        }
    }
}

private extension Array where Element == Substring {
    /// Groups joined with dashes, `size` to a line.
    func chunked(_ size: Int) -> [String] {
        stride(from: 0, to: count, by: size).map { self[$0..<Swift.min($0 + size, count)].joined(separator: "-") }
    }
}
