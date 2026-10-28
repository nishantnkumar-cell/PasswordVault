import SwiftUI
import VisionKit

/// A strong default for the "Generate" button: 20 characters, all classes.
func strongPassword() -> String {
    (try? generatePassword(options: GeneratorOptions(length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: true))) ?? ""
}

/// "08/29" or "0829" as (8, 2029); (0, 0) when it doesn't parse.
func parseExpiry(_ s: String) -> (UInt8, UInt16) {
    let kept = s.filter { $0.isNumber || $0 == "/" }
    let parts = kept.contains("/") ? kept.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        : [String(kept.prefix(2)), String(kept.dropFirst(2))]
    guard parts.count >= 2, let m = Int(parts[0]), var y = Int(parts[1]), (1...12).contains(m) else { return (0, 0) }
    if y < 100 { y += 2000 }
    return (UInt8(m), UInt16(clamping: y))
}

private struct UrlDraft: Identifiable {
    let id = UUID()
    var url: String
    var sub: Bool
}

private struct FieldDraft: Identifiable {
    let id = UUID()
    var name: String
    var value: String
    var hidden: Bool
}

/// Create or edit an item. `onDone` gets the saved ID, or nil on cancel.
struct ItemEditorView: View {
    @Environment(VaultModel.self) private var vault
    let id: String?
    let kind: Kind
    let existing: ItemDetail?
    let onDone: (String?) -> Void
    /// Fills a new login from a code-setup link.
    let setup: CodeSetup?

    @State private var title = ""
    @State private var username = ""
    @State private var password = ""
    @State private var showPassword = false
    @State private var urls: [UrlDraft] = []
    @State private var totpInput = ""
    @State private var removeTotp = false
    @State private var scanning = false
    @State private var holder = ""
    @State private var number = ""
    @State private var expiry = ""
    @State private var cvv = ""
    @State private var pin = ""
    @State private var person = IdentityRecord(honorific: "", givenName: "", middleName: "", familyName: "", company: "", email: "", phone: "",
                                               address1: "", address2: "", address3: "", city: "", region: "", postcode: "", country: "")
    @State private var fields: [FieldDraft] = []
    @State private var notes = ""
    @State private var error: String?
    @State private var loaded = false

    init(id: String?, kind: Kind, existing: ItemDetail?, setup: CodeSetup? = nil, onDone: @escaping (String?) -> Void) {
        self.id = id
        self.kind = existing?.kind ?? kind
        self.existing = existing
        self.setup = setup
        self.onDone = onDone
    }

    var body: some View {
        Form {
            Section {
                TextField(titlePrompt, text: $title).font(.title3.weight(.semibold))
            }
            switch kind {
            case .login: loginSections
            case .card: cardSection
            case .identity: identitySection
            case .note: EmptyView()
            }
            if kind == .login || kind == .note { totpSection }
            fieldsSection
            Section("Notes") {
                TextField(kind == .note ? "Write anything" : "Notes", text: $notes, axis: .vertical)
                    .lineLimit(kind == .note ? 8 ... 30 : 3 ... 12)
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle(id == nil ? "New \(kind.label)" : "Edit \(kind.label)")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(role: .cancel) { onDone(nil) } label: { Label("Cancel", systemImage: "xmark") }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(role: .confirm, action: save) { Label("Save", systemImage: "checkmark") }
                    .disabled(title.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .sheet(isPresented: $scanning) {
            QRScanner { code in
                totpInput = code
                scanning = false
            }
            .ignoresSafeArea()
        }
        .onAppear(perform: load)
    }

    private var titlePrompt: String {
        switch kind {
        case .login: return "Title, e.g. Example Mail"
        case .note: return "Title"
        case .card: return "Title, e.g. Everyday Visa"
        case .identity: return "Title, e.g. Home"
        }
    }

    private func load() {
        guard !loaded else { return }
        loaded = true
        guard let e = existing else {
            if kind == .login {
                password = strongPassword()
                urls = [UrlDraft(url: "", sub: false)]
            }
            if let setup {
                title = setup.issuer.isEmpty ? setup.account : setup.issuer
                username = setup.account
                // The site's password is already set; don't suggest a new one.
                password = ""
                totpInput = setup.uri
            }
            return
        }
        title = e.title
        username = e.username
        password = e.password
        urls = e.urls.map { UrlDraft(url: $0.url, sub: $0.matchSubdomains) }
        if let c = e.card {
            holder = c.holder
            number = c.number
            expiry = c.expMonth > 0 ? String(format: "%02d/%02d", Int(c.expMonth), Int(c.expYear) % 100) : ""
            cvv = c.cvv
            pin = c.pin
        }
        if let p = e.identity { person = p }
        fields = e.fields.map { FieldDraft(name: $0.name, value: $0.value, hidden: $0.hidden) }
        notes = e.notes
    }

    // MARK: Sections

    @ViewBuilder private var loginSections: some View {
        Section {
            TextField("Username or email", text: $username)
                .textContentType(.username)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            HStack {
                Group {
                    if showPassword { TextField("Password", text: $password) } else { SecureField("Password", text: $password) }
                }
                .font(.system(.body, design: .monospaced))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                Button { showPassword.toggle() } label: { Image(systemName: showPassword ? "eye.slash" : "eye") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(showPassword ? "Hide password" : "Show password")
                Button { password = strongPassword(); showPassword = true } label: { Image(systemName: "dice") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Generate a new password")
            }
        }
        Section {
            ForEach($urls) { $u in
                VStack(alignment: .leading, spacing: 6) {
                    TextField("example.com", text: $u.url)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Toggle("Also its subdomains", isOn: $u.sub).font(.subheadline)
                }
            }
            .onDelete { urls.remove(atOffsets: $0) }
            Button { urls.append(UrlDraft(url: "", sub: false)) } label: { Label("Add Website", systemImage: "plus") }
        } header: {
            Text("Websites")
        } footer: {
            Text("AutoFill offers this login only on these sites, so a look-alike site can't trick you into filling it.")
        }
    }

    @ViewBuilder private var totpSection: some View {
        Section {
            HStack {
                TextField(existing?.hasTotp == true ? "Paste a new key to replace it" : "Setup key or otpauth:// link", text: $totpInput)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                if DataScannerViewController.isSupported {
                    Button { scanning = true } label: { Image(systemName: "qrcode.viewfinder") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Scan QR code")
                }
            }
            if !totpInput.isEmpty {
                if let code = try? previewTotp(input: totpInput, now: UInt64(Date().timeIntervalSince1970)) {
                    Label("Current code: \(groupCode(code.code))", systemImage: "checkmark.circle").foregroundStyle(Palette.ok)
                } else {
                    Label("This isn't a key the vault understands yet.", systemImage: "exclamationmark.triangle").foregroundStyle(Palette.warn)
                }
            }
            if existing?.hasTotp == true && totpInput.isEmpty {
                Toggle("Remove one-time codes", isOn: $removeTotp)
            }
        } header: {
            Text("One-Time Codes")
        } footer: {
            Text("When a site shows a QR code for an authenticator app, scan it here or paste its setup key.")
        }
    }

    @ViewBuilder private var cardSection: some View {
        Section("Card") {
            TextField("Name on card", text: $holder).textContentType(.name)
            TextField("Card number", text: $number)
                .keyboardType(.numberPad)
                .textContentType(.creditCardNumber)
                .font(.system(.body, design: .monospaced))
            HStack {
                TextField("MM/YY", text: $expiry).keyboardType(.numbersAndPunctuation)
                Divider()
                SecureField("Security code", text: $cvv).keyboardType(.numberPad)
            }
            SecureField("PIN (optional)", text: $pin).keyboardType(.numberPad)
        }
    }

    @ViewBuilder private var identitySection: some View {
        Section("Name") {
            TextField("Title (Mx, Dr…)", text: $person.honorific)
            TextField("First name", text: $person.givenName).textContentType(.givenName)
            TextField("Middle name", text: $person.middleName).textContentType(.middleName)
            TextField("Last name", text: $person.familyName).textContentType(.familyName)
            TextField("Company", text: $person.company).textContentType(.organizationName)
        }
        Section("Contact") {
            TextField("Email", text: $person.email)
                .keyboardType(.emailAddress).textContentType(.emailAddress).textInputAutocapitalization(.never)
            TextField("Phone", text: $person.phone).keyboardType(.phonePad).textContentType(.telephoneNumber)
        }
        Section("Address") {
            TextField("Address line 1", text: $person.address1).textContentType(.streetAddressLine1)
            TextField("Address line 2", text: $person.address2).textContentType(.streetAddressLine2)
            TextField("Address line 3", text: $person.address3)
            TextField("City", text: $person.city).textContentType(.addressCity)
            TextField("State or region", text: $person.region).textContentType(.addressState)
            TextField("Postcode", text: $person.postcode).textContentType(.postalCode)
            TextField("Country", text: $person.country).textContentType(.countryName)
        }
    }

    @ViewBuilder private var fieldsSection: some View {
        Section("More Fields") {
            ForEach($fields) { $f in
                VStack(alignment: .leading, spacing: 6) {
                    TextField("Name", text: $f.name).font(.subheadline.weight(.medium))
                    if f.hidden { SecureField("Value", text: $f.value) } else { TextField("Value", text: $f.value) }
                    Toggle("Hidden", isOn: $f.hidden).font(.subheadline)
                }
            }
            .onDelete { fields.remove(atOffsets: $0) }
            Button { fields.append(FieldDraft(name: "", value: "", hidden: false)) } label: { Label("Add Field", systemImage: "plus") }
        }
    }

    // MARK: Saving

    private func save() {
        let (month, year) = parseExpiry(expiry)
        let totp: TotpEdit = !totpInput.trimmingCharacters(in: .whitespaces).isEmpty ? .set(input: totpInput)
            : removeTotp ? .remove : .keep
        let edit = ItemEdit(
            kind: kind,
            title: title,
            username: username,
            password: password,
            urls: urls.filter { !$0.url.trimmingCharacters(in: .whitespaces).isEmpty }
                .map { UrlRecord(url: $0.url, matchSubdomains: $0.sub, allowHttp: false) },
            totp: totp,
            card: kind == .card ? CardRecord(holder: holder, number: number, expMonth: month, expYear: year, cvv: cvv, pin: pin, brand: nil, numberValid: false) : nil,
            identity: kind == .identity ? person : nil,
            fields: fields.map { FieldRecord(name: $0.name, value: $0.value, hidden: $0.hidden, link: false) },
            notes: notes
        )
        do {
            onDone(try vault.save(id: id, edit: edit))
        } catch {
            self.error = describe(error)
        }
    }
}

/// Live QR scanning with VisionKit; returns the first QR code's text.
struct QRScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let vc = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])], isHighlightingEnabled: true)
        vc.delegate = context.coordinator
        try? vc.startScanning()
        return vc
    }

    func updateUIViewController(_ vc: DataScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let onCode: (String) -> Void
        private var done = false
        init(onCode: @escaping (String) -> Void) { self.onCode = onCode }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
            for case let .barcode(code) in items {
                guard !done, let text = code.payloadStringValue else { continue }
                done = true
                scanner.stopScanning()
                onCode(text)
            }
        }
    }
}
