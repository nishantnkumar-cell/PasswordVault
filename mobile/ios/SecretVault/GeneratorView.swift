import SwiftUI

/// Makes random passwords with the same generator as the desktop app.
struct GeneratorView: View {
    @AppStorage("gen.length", store: AppGroup.defaults) private var length = 20.0
    @AppStorage("gen.lower", store: AppGroup.defaults) private var lower = true
    @AppStorage("gen.upper", store: AppGroup.defaults) private var upper = true
    @AppStorage("gen.digits", store: AppGroup.defaults) private var digits = true
    @AppStorage("gen.symbols", store: AppGroup.defaults) private var symbols = true
    @AppStorage("gen.ambiguous", store: AppGroup.defaults) private var avoidAmbiguous = true
    @State private var password = ""
    @State private var copied = false

    private var options: GeneratorOptions {
        GeneratorOptions(length: UInt32(length), lower: lower, upper: upper, digits: digits, symbols: symbols, avoidAmbiguous: avoidAmbiguous)
    }

    var body: some View {
        Form {
            Section {
                VStack(spacing: 16) {
                    Text(password.isEmpty ? "Pick at least one kind of character" : password)
                        .font(.system(.title3, design: .monospaced).weight(.medium))
                        .multilineTextAlignment(.center)
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
                VStack(alignment: .leading) {
                    Text("Length: \(Int(length))").font(.subheadline.weight(.medium))
                    Slider(value: $length, in: 8...64, step: 1)
                }
                Toggle("Lowercase (a–z)", isOn: $lower)
                Toggle("Uppercase (A–Z)", isOn: $upper)
                Toggle("Digits (0–9)", isOn: $digits)
                Toggle("Symbols (!#%…)", isOn: $symbols)
                Toggle("Avoid look-alikes (l, 1, O, 0)", isOn: $avoidAmbiguous)
            } header: {
                Text("Options")
            } footer: {
                Text("Twenty characters of every kind is far beyond what anyone can guess. Some sites limit length or symbols; turn options off to fit them.")
            }
        }
        .navigationTitle("Generator")
        .onAppear { if password.isEmpty { regenerate() } }
        .onChange(of: options) { regenerate() }
    }

    private func regenerate() {
        copied = false
        withAnimation { password = (try? generatePassword(options: options)) ?? "" }
    }
}
