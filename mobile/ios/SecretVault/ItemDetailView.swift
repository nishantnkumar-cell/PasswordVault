import SwiftUI

struct ItemDetailView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    let id: String
    @State private var editing = false
    @State private var showPassword = false
    @State private var confirmDelete = false
    @State private var copied: String?

    var body: some View {
        let _ = vault.revision
        if let item = vault.item(id) {
            content(item)
        } else {
            ContentUnavailableView("Item Deleted", systemImage: "trash")
        }
    }

    private func content(_ item: ItemDetail) -> some View {
        List {
            Section {
                VStack(spacing: 8) {
                    LetterTile(title: item.title, size: 72)
                    Text(item.title).font(.title2.bold()).multilineTextAlignment(.center)
                    Text("\(item.kind.label) · edited \(Date(timeIntervalSince1970: TimeInterval(item.modified)), format: .relative(presentation: .named))")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .listRowBackground(Color.clear)
            }

            if item.hasTotp {
                Section { TotpRow(id: id, copy: copy) }
            }

            switch item.kind {
            case .login: loginSection(item)
            case .card: cardSection(item)
            case .identity: identitySection(item)
            case .note: EmptyView()
            }

            if let key = item.key {
                Section("Key") {
                    Text("\(key). Your computer's vault daemon uses it for SSH and Git signing; the phone app shows it but does not use it.")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
            }

            if !item.fields.isEmpty {
                Section("More Fields") {
                    ForEach(Array(item.fields.enumerated()), id: \.offset) { _, f in
                        FieldRow(label: f.name, value: f.value, secret: f.hidden, copy: copy)
                    }
                }
            }

            if !item.notes.isEmpty {
                Section("Notes") { Text(item.notes).textSelection(.enabled) }
            }
        }
        .listStyle(.insetGrouped)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .primaryAction) { Button("Edit") { editing = true } }
            ToolbarItem(placement: .secondaryAction) {
                Button(role: .destructive) { confirmDelete = true } label: { Label("Delete", systemImage: "trash") }
            }
        }
        .sheet(isPresented: $editing) {
            NavigationStack { ItemEditorView(id: id, kind: item.kind, existing: item) { _ in editing = false } }
        }
        .confirmationDialog("Delete \(item.title)?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) { try? vault.delete(id: id); dismiss() }
        } message: {
            Text("It is deleted on every device that syncs this vault.")
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
    }

    private func copy(_ label: String, _ value: String, _ sensitive: Bool) {
        SecureClipboard.copy(value, sensitive: sensitive)
        copied = sensitive ? "\(label) copied. Clears in \(Prefs.clipboardSeconds) s." : "\(label) copied."
        Task {
            try? await Task.sleep(for: .seconds(2))
            copied = nil
        }
    }

    @ViewBuilder private func loginSection(_ item: ItemDetail) -> some View {
        Section {
            if !item.username.isEmpty { FieldRow(label: "Username", value: item.username, secret: false, copy: copy) }
            if !item.password.isEmpty { FieldRow(label: "Password", value: item.password, secret: true, copy: copy) }
        }
        if !item.urls.isEmpty {
            Section("AutoFill Is Bound To") {
                ForEach(item.urls, id: \.url) { u in
                    HStack(spacing: 10) {
                        Image(systemName: "checkmark.shield").foregroundStyle(Palette.ok)
                        VStack(alignment: .leading) {
                            Text(u.url).font(.system(.subheadline, design: .monospaced))
                            Text(u.matchSubdomains ? "this site and its subdomains" : "this site only")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button { if let url = URL(string: u.url) { openURL(url) } } label: {
                            Image(systemName: "arrow.up.right.square")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Open \(u.url)")
                    }
                }
            }
        }
    }

    @ViewBuilder private func cardSection(_ item: ItemDetail) -> some View {
        if let c = item.card {
            Section {
                CardArt(card: c, shown: showPassword)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
                    .onTapGesture { showPassword.toggle() }
            }
            Section {
                if !c.number.isEmpty { FieldRow(label: "Card number", value: c.number, secret: true, copy: copy) }
                if !c.cvv.isEmpty { FieldRow(label: "Security code", value: c.cvv, secret: true, copy: copy) }
                if !c.pin.isEmpty { FieldRow(label: "PIN", value: c.pin, secret: true, copy: copy) }
            } footer: {
                if !c.numberValid && !c.number.isEmpty {
                    Text("This number fails the card checksum; check it for a typo.").foregroundStyle(Palette.warn)
                }
            }
        }
    }

    @ViewBuilder private func identitySection(_ item: ItemDetail) -> some View {
        if let p = item.identity {
            let name = [p.honorific, p.givenName, p.middleName, p.familyName].filter { !$0.isEmpty }.joined(separator: " ")
            let place = [p.city, p.region, p.postcode].filter { !$0.isEmpty }.joined(separator: ", ")
            let address = [p.address1, p.address2, p.address3, place, p.country].filter { !$0.isEmpty }.joined(separator: "\n")
            Section {
                ForEach([("Name", name), ("Company", p.company), ("Email", p.email), ("Phone", p.phone), ("Address", address)]
                    .filter { !$0.1.isEmpty }, id: \.0) { row in
                    FieldRow(label: row.0, value: row.1, secret: false, copy: copy)
                }
            }
        }
    }
}

/// A labelled value with copy (and show, for secrets).
struct FieldRow: View {
    let label: String
    let value: String
    let secret: Bool
    let copy: (String, String, Bool) -> Void
    @State private var shown = false

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.subheadline).foregroundStyle(.secondary)
                if secret && !shown {
                    Text("••••••••••••").font(.body).accessibilityLabel("Hidden")
                } else {
                    Text(value).font(secret ? .system(.body, design: .monospaced) : .body).textSelection(.enabled)
                }
            }
            Spacer()
            if secret {
                Button { shown.toggle() } label: { Image(systemName: shown ? "eye.slash" : "eye") }
                    .buttonStyle(.glass)
                    .accessibilityLabel(shown ? "Hide \(label)" : "Show \(label)")
            }
            Button { copy(label, value, secret) } label: { Image(systemName: "doc.on.doc") }
                .buttonStyle(secret ? AnyPrimitiveButtonStyle(.glassProminent) : AnyPrimitiveButtonStyle(.glass))
                .accessibilityLabel("Copy \(label)")
        }
    }
}

/// Type-erases the two glass button styles.
struct AnyPrimitiveButtonStyle: PrimitiveButtonStyle {
    private let make: (Configuration) -> AnyView
    init<S: PrimitiveButtonStyle>(_ s: S) { make = { AnyView(s.makeBody(configuration: $0)) } }
    func makeBody(configuration: Configuration) -> some View { make(configuration) }
}

struct TotpRow: View {
    @Environment(VaultModel.self) private var vault
    let id: String
    let copy: (String, String, Bool) -> Void

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            if let code = vault.totp(id) {
                HStack(spacing: 14) {
                    TotpRing(remaining: Int(code.remaining), period: Int(code.period), size: 40)
                    VStack(alignment: .leading, spacing: 0) {
                        Text("One-time code · \(code.remaining) s left").font(.subheadline).foregroundStyle(.secondary)
                        Text(groupCode(code.code)).font(.system(size: 28, weight: .semibold, design: .monospaced))
                            .contentTransition(.numericText())
                    }
                    Spacer()
                    Button { copy("One-time code", code.code, true) } label: { Image(systemName: "doc.on.doc") }
                        .buttonStyle(.glassProminent)
                        .accessibilityLabel("Copy one-time code")
                }
            }
        }
    }
}

struct CardArt: View {
    let card: CardRecord
    let shown: Bool

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text(card.holder).font(.headline)
                Spacer()
                Text(card.brand?.uppercased() ?? "").font(.headline.weight(.heavy))
            }
            Spacer()
            Text(shown ? card.number.chunked(4) : "•••• •••• •••• \(card.number.suffix(4))")
                .font(.system(.title2, design: .monospaced))
            Spacer()
            if card.expMonth > 0 {
                Text(String(format: "Expires %02d/%02d", Int(card.expMonth), Int(card.expYear) % 100)).font(.subheadline)
            }
        }
        .foregroundStyle(.white)
        .padding(22)
        .frame(maxWidth: 420)
        .aspectRatio(1.586, contentMode: .fit)
        .background(
            LinearGradient(colors: [Color(light: 0x1D3FA8, dark: 0x1D3FA8), Color(light: 0x2C55D4, dark: 0x2C55D4), Color(light: 0x5B7BE8, dark: 0x4A6CF0)],
                           startPoint: .topLeading, endPoint: .bottomTrailing),
            in: .rect(cornerRadius: 24, style: .continuous)
        )
        .frame(maxWidth: .infinity)
        .accessibilityLabel("\(card.brand ?? "Card") ending \(String(card.number.suffix(4)))")
    }
}

extension String {
    func chunked(_ n: Int) -> String {
        var out = ""
        for (i, c) in enumerated() {
            if i > 0 && i % n == 0 { out.append(" ") }
            out.append(c)
        }
        return out
    }
}
