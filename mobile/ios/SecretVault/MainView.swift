import SwiftUI

/// Item categories, as in the desktop sidebar.
enum Category: String, CaseIterable, Identifiable {
    case all = "All Items", logins = "Logins", notes = "Secure Notes", cards = "Cards",
         identities = "Identities", codes = "One-Time Codes", keys = "SSH and PGP Keys"

    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .all: return "tray.full"
        case .logins: return "key"
        case .notes: return "note.text"
        case .cards: return "creditcard"
        case .identities: return "person.text.rectangle"
        case .codes: return "clock.badge.checkmark"
        case .keys: return "terminal"
        }
    }

    func matches(_ s: ItemSummary) -> Bool {
        switch self {
        case .all: return true
        case .logins: return s.kind == .login
        case .notes: return s.kind == .note && !s.hasKey
        case .cards: return s.kind == .card
        case .identities: return s.kind == .identity
        case .codes: return s.hasTotp
        case .keys: return s.hasKey
        }
    }
}

extension ItemSummary {
    func matches(_ query: String) -> Bool {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        if q.isEmpty { return true }
        return title.lowercased().contains(q) || subtitle.lowercased().contains(q) || (host?.contains(q) ?? false)
    }
}

/// Phones (and a folded foldable) get a Liquid Glass tab bar with a search
/// tab; iPad and wide windows (an unfolded foldable, Split View, Stage
/// Manager) get three columns like the desktop app.
struct MainView: View {
    @Environment(\.horizontalSizeClass) private var width
    @Environment(VaultModel.self) private var vault

    var body: some View {
        @Bindable var vault = vault
        Group {
            if width == .regular { SplitLayout() } else { TabLayout() }
        }
        .sheet(item: $vault.pendingCodeSetup) { setup in
            NavigationStack {
                ItemEditorView(id: nil, kind: .login, existing: nil, setup: setup) { _ in vault.pendingCodeSetup = nil }
            }
        }
    }
}

private struct TabLayout: View {
    @State private var query = ""

    var body: some View {
        TabView {
            Tab("Items", systemImage: "rectangle.stack") {
                NavigationStack { ItemListView(category: .all, query: "", selection: nil).navigationTitle("Items") }
            }
            Tab("Codes", systemImage: "clock") {
                NavigationStack { CodesView() }
            }
            Tab("Generator", systemImage: "dice") {
                NavigationStack { GeneratorView() }
            }
            Tab("Settings", systemImage: "gearshape") {
                NavigationStack { SettingsView() }
            }
            Tab(role: .search) {
                NavigationStack {
                    ItemListView(category: .all, query: query, selection: nil)
                        .navigationTitle("Search")
                        .searchable(text: $query, prompt: "Titles, users and sites")
                }
            }
        }
        .tabBarMinimizeBehavior(.onScrollDown)
    }
}

private enum SidebarEntry: Hashable {
    case category(Category)
    case codes, generator, settings
}

private struct SplitLayout: View {
    @Environment(VaultModel.self) private var vault
    @State private var entry: SidebarEntry? = .category(.all)
    @State private var selected: String?
    @State private var query = ""

    var body: some View {
        NavigationSplitView {
            List(selection: $entry) {
                Section {
                    ForEach(Category.allCases) { c in
                        let n = vault.items.filter(c.matches).count
                        if c == .all || n > 0 {
                            Label(c.rawValue, systemImage: c.symbol)
                                .badge(n)
                                .tag(SidebarEntry.category(c))
                        }
                    }
                }
                Section("Tools") {
                    // "Codes", as on the iPhone tab bar; "One-Time Codes" above is the item filter.
                    Label("Codes", systemImage: "clock").tag(SidebarEntry.codes)
                    Label("Generator", systemImage: "dice").tag(SidebarEntry.generator)
                    Label("Settings", systemImage: "gearshape").tag(SidebarEntry.settings)
                }
            }
            .navigationTitle("Secret Vault")
            .safeAreaInset(edge: .bottom) { StatusPill().padding() }
        } content: {
            Group {
                switch entry {
                case .category(let c)?:
                    ItemListView(category: c, query: query, selection: $selected)
                        .navigationTitle(c.rawValue)
                        .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always), prompt: "Search")
                case .codes?: CodesView()
                case .generator?: GeneratorView()
                case .settings?: SettingsView()
                case nil: Text("Pick a category").foregroundStyle(.secondary)
                }
            }
            // Wide enough for titles and usernames in portrait too.
            .navigationSplitViewColumnWidth(min: 300, ideal: 340, max: 420)
        } detail: {
            NavigationStack {
                if let id = selected, case .category = entry {
                    ItemDetailView(id: id).id(id)
                } else {
                    ContentUnavailableView("No Item Selected", systemImage: "key.viewfinder", description: Text("Pick an item to see its details."))
                }
            }
        }
        .onChange(of: entry) { _, now in
            // Don't keep showing an item the new list doesn't contain.
            guard case .category(let c)? = now, let id = selected,
                  vault.items.contains(where: { $0.id == id && c.matches($0) }) else { selected = nil; return }
        }
    }
}

/// "Unlocked · synced 1 min ago", with a Lock button, as on the desktop.
struct StatusPill: View {
    @Environment(VaultModel.self) private var vault

    var body: some View {
        HStack(spacing: 8) {
            Circle().fill(vault.sync.error == nil ? Palette.ok : Palette.warn).frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 0) {
                Text("Unlocked").font(.subheadline.weight(.medium))
                if let last = vault.sync.last {
                    Text("Synced \(last, format: .relative(presentation: .named))").font(.caption).foregroundStyle(.secondary)
                } else if let e = vault.sync.error {
                    Text(e).font(.caption).foregroundStyle(Palette.warn).lineLimit(1)
                }
            }
            Spacer()
            Button("Lock") { vault.lock() }.buttonStyle(.glass)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .glassEffect(.regular, in: .rect(cornerRadius: 18))
    }
}
