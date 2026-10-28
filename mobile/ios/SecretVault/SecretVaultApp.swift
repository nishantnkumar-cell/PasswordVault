import SwiftUI

@main
struct SecretVaultApp: App {
    @State private var vault = VaultModel()
    @Environment(\.scenePhase) private var phase
    @State private var hiddenAt: Date?

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(vault)
                .tint(Palette.accent)
                // Hide contents in the app switcher.
                .overlay { if phase != .active && vault.isUnlocked { PrivacyCover() } }
                // A verification-code setup link or QR code (iOS lists us
                // under "Set Up Codes In" because we open otpauth links).
                .onOpenURL { url in
                    if let setup = CodeSetup(url: url) { vault.pendingCodeSetup = setup }
                }
        }
        .onChange(of: phase) { _, now in
            switch now {
            case .background:
                hiddenAt = Date()
                if Prefs.autoLockSeconds == 0 { vault.lock() }
            case .active:
                if let t = hiddenAt, Date().timeIntervalSince(t) >= Double(Prefs.autoLockSeconds) {
                    vault.lock()
                } else if vault.isUnlocked {
                    vault.refreshSuggestions()
                    Task { await vault.syncNow() }
                }
                hiddenAt = nil
            default:
                break
            }
        }
    }
}

private struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.ultraThickMaterial).ignoresSafeArea()
            AppIconView(size: 72)
        }
    }
}

struct RootView: View {
    @Environment(VaultModel.self) private var vault
    @State private var recoveryCode: String?

    var body: some View {
        Group {
            if let code = recoveryCode {
                RecoveryCodeView(code: code) { recoveryCode = nil }
            } else {
                switch vault.state {
                case .noVault: WelcomeView { recoveryCode = $0 }
                case let .locked(quick, hasPassword): UnlockView(quickUnlock: quick, hasPassword: hasPassword)
                case .unlocked: MainView()
                }
            }
        }
        .animation(.smooth, value: vault.state)
    }
}
