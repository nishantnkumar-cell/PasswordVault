import SwiftUI

/// The generator's styles, as on the desktop.
enum GenStyle: String, CaseIterable, Identifiable {
    case random, words, apple
    var id: Self { self }

    var label: String {
        switch self {
        case .random: return "Random"
        case .words: return "3 Words"
        case .apple: return "Apple Style"
        }
    }
}

/// The settings the Generator tab saved, which the editor's dice button uses too.
enum GeneratorPrefs {
    private static var d: UserDefaults { AppGroup.defaults }

    static var style: PasswordStyle {
        let kind = GenStyle(rawValue: d.string(forKey: "gen.style") ?? "") ?? .random
        switch kind {
        case .random:
            return .random(options: GeneratorOptions(
                length: UInt32(d.object(forKey: "gen.length") as? Double ?? 20),
                lower: d.object(forKey: "gen.lower") as? Bool ?? true,
                upper: d.object(forKey: "gen.upper") as? Bool ?? true,
                digits: d.object(forKey: "gen.digits") as? Bool ?? true,
                symbols: d.object(forKey: "gen.symbols") as? Bool ?? true,
                avoidAmbiguous: d.object(forKey: "gen.ambiguous") as? Bool ?? true))
        case .words:
            return .words(
                words: UInt32(d.object(forKey: "gen.words") as? Double ?? 3),
                separator: d.string(forKey: "gen.separator") ?? "",
                capitalize: d.object(forKey: "gen.capitalize") as? Bool ?? true,
                numberAndSymbol: d.object(forKey: "gen.numberSymbol") as? Bool ?? false)
        case .apple:
            return .apple
        }
    }
}

/// Makes passwords with the same generator as the desktop app: random
/// characters, three random words (the UK NCSC's advice) or Apple style.
struct GeneratorView: View {
    @AppStorage("gen.style", store: AppGroup.defaults) private var kind = GenStyle.random
    @AppStorage("gen.length", store: AppGroup.defaults) private var length = 20.0
    @AppStorage("gen.lower", store: AppGroup.defaults) private var lower = true
    @AppStorage("gen.upper", store: AppGroup.defaults) private var upper = true
    @AppStorage("gen.digits", store: AppGroup.defaults) private var digits = true
    @AppStorage("gen.symbols", store: AppGroup.defaults) private var symbols = true
    @AppStorage("gen.ambiguous", store: AppGroup.defaults) private var avoidAmbiguous = true
    @AppStorage("gen.words", store: AppGroup.defaults) private var words = 3.0
    @AppStorage("gen.separator", store: AppGroup.defaults) private var separator = ""
    @AppStorage("gen.capitalize", store: AppGroup.defaults) private var capitalize = true
    @AppStorage("gen.numberSymbol", store: AppGroup.defaults) private var numberAndSymbol = false
    @State private var password = ""
    @State private var copied = false

    private var style: PasswordStyle {
        switch kind {
        case .random:
            return .random(options: GeneratorOptions(length: UInt32(length), lower: lower, upper: upper, digits: digits, symbols: symbols, avoidAmbiguous: avoidAmbiguous))
        case .words:
            return .words(words: UInt32(words), separator: separator, capitalize: capitalize, numberAndSymbol: numberAndSymbol)
        case .apple:
            return .apple
        }
    }

    var body: some View {
        Form {
            Section {
                VStack(spacing: 16) {
                    Text(password.isEmpty ? "Pick at least one kind of character" : password)
                        .font(.system(.title3, design: .monospaced).weight(.medium))
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                        .contentTransition(.opacity)
                        .frame(maxWidth: .infinity, minHeight: 64)
                    HStack(spacing: 12) {
                        Button { regenerate() } label: { Label("New", systemImage: "arrow.clockwise").frame(maxWidth: .infinity) }
                            .buttonStyle(.glass)
                        Button {
                            SecureClipboard.copy(password, sensitive: true)
                            copied = true
                        } label: {
                            Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.glassProminent)
                        .disabled(password.isEmpty)
                    }
                    .controlSize(.large)
                }
                .padding(.vertical, 8)
                .listRowBackground(Color.clear)
            } footer: {
                if copied { Text("Clears from the clipboard in \(Prefs.clipboardSeconds) seconds.") }
            }

            Section {
                Picker("Style", selection: $kind) {
                    ForEach(GenStyle.allCases) { Text($0.label).tag($0) }
                }
                .pickerStyle(.segmented)
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets())
            } footer: {
                Text(about).fixedSize(horizontal: false, vertical: true)
            }

            switch kind {
            case .random:
                Section("Options") {
                    VStack(alignment: .leading) {
                        Text("Length: \(Int(length))").font(.subheadline.weight(.medium))
                        Slider(value: $length, in: 8...64, step: 1)
                    }
                    Toggle("Lowercase (a–z)", isOn: $lower)
                    Toggle("Uppercase (A–Z)", isOn: $upper)
                    Toggle("Digits (0–9)", isOn: $digits)
                    Toggle("Symbols (!#%…)", isOn: $symbols)
                    Toggle("Avoid look-alikes (l, 1, O, 0)", isOn: $avoidAmbiguous)
                }
            case .words:
                Section("Options") {
                    Stepper("Words: \(Int(words))", value: $words, in: 3...10)
                    Picker("Between Words", selection: $separator) {
                        Text("Nothing").tag("")
                        Text("-").tag("-")
                        Text(".").tag(".")
                        Text("Space").tag(" ")
                    }
                    Toggle("Capitalize Each Word", isOn: $capitalize)
                    Toggle("Add a Number and Symbol", isOn: $numberAndSymbol)
                }
            case .apple:
                EmptyView()
            }
        }
        .navigationTitle("Generator")
        .onAppear { if password.isEmpty { regenerate() } }
        .onChange(of: style) { regenerate() }
    }

    private var about: String {
        let bits = Int(passwordStrength(style: style).rounded())
        switch kind {
        case .random:
            return "Random characters: about \(bits) bits. Twenty characters of every kind is far beyond what anyone can guess. Some sites limit length or symbols; turn options off to fit them."
        case .words:
            return "Three random words, as the UK's National Cyber Security Centre recommends: easy to remember and type, like CupFishBiscuit. About \(bits) bits; use four or more words for anything that matters most."
        case .apple:
            return "Like the passwords iPhone suggests: three groups of six letters with one capital and one digit, easy to type on a phone keyboard. About \(bits) bits."
        }
    }

    private func regenerate() {
        copied = false
        withAnimation { password = (try? generateStyled(style: style)) ?? "" }
    }
}
