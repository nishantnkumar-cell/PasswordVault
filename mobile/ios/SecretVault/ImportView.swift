import SwiftUI
import UniformTypeIdentifiers

/// Settings › Import from Another App: a Bitwarden JSON or a password CSV
/// (Apple Passwords, Safari, Chrome, Edge, Firefox) picked in Files.
struct ImportView: View {
    @Environment(VaultModel.self) private var vault
    @State private var picking = false
    @State private var picked: URL?
    @State private var result: ImportResult?
    @State private var deleted = false
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                Text("Export your passwords from the other app as a file, save it in Files, then choose it here. Every login, note, card and identity in it becomes a new item.")
            }
            Section("How to Export") {
                Step(app: "Apple Passwords", how: "On a Mac, open the Passwords app and choose File › Export All Passwords to File. Saves a CSV, with one-time codes. Put it in iCloud Drive to reach it here.")
                Step(app: "Bitwarden", how: "Tools › Export Vault, format .json. Choose the unencrypted export.")
                Step(app: "Chrome or Edge", how: "Settings › Passwords › Export passwords. Saves a CSV.")
                Step(app: "Firefox", how: "Passwords › ⋯ › Export Passwords. Saves a CSV.")
            }
            Section {
                Button { picking = true } label: { Label("Choose Export File", systemImage: "doc.badge.plus") }
            } footer: {
                Text("Importing twice adds the items twice.")
            }
            if let result {
                Section {
                    Label("Imported \(result.imported) item\(result.imported == 1 ? "" : "s") from the \(result.format) file.", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(Palette.ok)
                    if result.skipped > 0 {
                        Text("\(result.skipped) entr\(result.skipped == 1 ? "y" : "ies") had a type the vault doesn't hold (such as Bitwarden SSH keys) and were left out.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    if let picked, !deleted {
                        Button(role: .destructive) {
                            do { try vault.deleteFile(picked); deleted = true }
                            catch { self.error = "Could not delete the file: \(describe(error)) Delete it in Files." }
                        } label: { Label("Delete the Export File", systemImage: "trash") }
                    } else if deleted {
                        Label("Export file deleted.", systemImage: "trash").foregroundStyle(.secondary)
                    }
                } footer: {
                    if !deleted {
                        Text("The export holds every password in plain text. Delete it now, and from Recently Deleted in Files.")
                    }
                }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("Import")
        .fileImporter(isPresented: $picking, allowedContentTypes: [.commaSeparatedText, .json, .plainText, .data]) { r in
            guard let url = try? r.get() else { return }
            error = nil
            result = nil
            deleted = false
            do {
                result = try vault.importFile(url)
                picked = url
            } catch {
                self.error = describe(error)
            }
        }
    }
}

private struct Step: View {
    let app: String
    let how: String
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(app).font(.body.weight(.medium))
            Text(how).font(.subheadline).foregroundStyle(.secondary)
        }
    }
}
