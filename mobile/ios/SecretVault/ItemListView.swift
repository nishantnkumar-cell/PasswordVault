import SwiftUI

struct ItemListView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(\.horizontalSizeClass) private var width
    let category: Category
    let query: String
    /// Set in the three-column layout; nil on phones, which push the detail.
    var selection: Binding<String?>?
    @State private var newKind: Kind?
    @State private var filter: Category = .all

    private var shown: [ItemSummary] {
        let c = width == .regular ? category : filter
        return vault.items.filter { c.matches($0) && $0.matches(query) }
    }

    var body: some View {
        Group {
            if let selection {
                List(selection: selection) { rows }
            } else {
                List { rows }
                    .navigationDestination(for: String.self) { ItemDetailView(id: $0) }
            }
        }
        .listStyle(.insetGrouped)
        .overlay {
            if shown.isEmpty {
                if vault.items.isEmpty {
                    ContentUnavailableView {
                        Label("No Items Yet", systemImage: "key")
                    } description: {
                        Text("Add your first login, or turn on Sync in Settings to bring in your computer's vault.")
                    } actions: {
                        Button("New Login") { newKind = .login }.buttonStyle(.glassProminent)
                    }
                } else if !query.isEmpty {
                    ContentUnavailableView.search(text: query)
                }
            }
        }
        .toolbar {
            if width != .regular {
                ToolbarItem(placement: .topBarLeading) {
                    // The app icon, green while unlocked; tapping it locks.
                    Button { vault.lock() } label: {
                        Label { Text("Lock") } icon: { AppIconView(size: 28, unlocked: true) }
                    }
                    .accessibilityLabel("Lock")
                    .accessibilityHint("The vault is unlocked")
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    ForEach([Kind.login, .note, .card, .identity], id: \.self) { k in
                        Button { newKind = k } label: { Label(k.label, systemImage: k.symbol) }
                    }
                } label: {
                    Label("New Item", systemImage: "plus")
                }
            }
        }
        .sheet(item: $newKind) { k in
            NavigationStack {
                ItemEditorView(id: nil, kind: k, existing: nil) { saved in
                    newKind = nil
                    if let saved { selection?.wrappedValue = saved }
                }
            }
        }
        .refreshable { await vault.syncNow() }
    }

    @ViewBuilder private var rows: some View {
        if width != .regular && query.isEmpty {
            Section {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(Category.allCases) { c in
                            let n = vault.items.filter(c.matches).count
                            if c == .all || n > 0 {
                                Button { filter = c } label: {
                                    Text(c == .all ? "All \(n)" : c.rawValue).font(.subheadline.weight(.medium))
                                }
                                .buttonStyle(.glass)
                                .tint(c == filter ? Palette.accent : nil)
                            }
                        }
                    }
                    .padding(.vertical, 4)
                }
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
            }
        }
        Section {
            ForEach(shown) { item in
                if selection != nil {
                    ItemRow(item: item).tag(item.id)
                } else {
                    NavigationLink(value: item.id) { ItemRow(item: item) }
                }
            }
        }
    }
}

extension Kind: Identifiable {
    public var id: Self { self }
}

struct ItemRow: View {
    let item: ItemSummary

    var body: some View {
        HStack(spacing: 12) {
            LetterTile(title: item.title)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title).font(.body.weight(.medium)).lineLimit(2)
                // Middle truncation keeps both ends of a long email address.
                Text(item.subtitle.isEmpty ? item.kind.label : item.subtitle)
                    .font(.subheadline).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 4)
            if item.hasKey {
                Tag(text: "Key")
            } else if item.hasTotp {
                Tag(text: "2FA")
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}

struct Tag: View {
    let text: String
    var body: some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .foregroundStyle(Palette.accent)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(Palette.accent.opacity(0.12), in: .rect(cornerRadius: 8))
    }
}
