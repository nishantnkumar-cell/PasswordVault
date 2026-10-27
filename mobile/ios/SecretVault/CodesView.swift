import SwiftUI

/// Every one-time code in one place, like an authenticator app. Tap a tile to
/// copy its code. The grid adds columns as the window widens, so an iPad or
/// an unfolded foldable shows several at once.
struct CodesView: View {
    @Environment(VaultModel.self) private var vault
    @State private var query = ""
    @State private var copied: String?

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
        .searchable(text: $query, prompt: "Search codes")
        .overlay {
            if shown.isEmpty {
                ContentUnavailableView {
                    Label(query.isEmpty ? "No One-Time Codes" : "No Matches", systemImage: "clock.badge.checkmark")
                } description: {
                    Text(query.isEmpty ? "Edit a login and scan the site's QR code to keep its two-factor codes here." : "Try another name.")
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
                    Text(item.title).font(.subheadline.weight(.medium)).lineLimit(1)
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
