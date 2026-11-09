import SwiftUI

/// Keyboard shortcuts for an iPad (or iPhone) with a keyboard. They appear
/// in the iPadOS menu bar and in the list shown while ⌘ is held.
///
/// | Shortcut | Does |
/// | --- | --- |
/// | ⌘N | New login |
/// | ⌥⌘N | New window |
/// | ⌘F | Search (three-column layout) |
/// | ⌘E | Edit the open item |
/// | ⇧⌘C | Copy the password |
/// | ⌥⌘C | Copy the username |
/// | ⌃⌘C | Copy the one-time code |
/// | ⌘R | Sync now |
/// | ⌘L | Lock |
struct VaultCommands: Commands {
    let vault: VaultModel
    @FocusedValue(\.newItem) private var newItem
    @FocusedValue(\.search) private var search
    @FocusedValue(\.itemActions) private var item
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        let open = vault.state == .unlocked
        CommandGroup(replacing: .newItem) {
            Button("New Login") { newItem?.run(.login) }
                .keyboardShortcut("n")
                .disabled(!open || newItem == nil)
            Menu("New Item") {
                ForEach([Kind.note, .card, .identity], id: \.self) { k in
                    Button(k.label) { newItem?.run(k) }
                }
                Button("SSH Key") { newItem?.run(nil) }
            }
            .disabled(!open || newItem == nil)
            Divider()
            Button("New Window") { openWindow(id: "main") }
                .keyboardShortcut("n", modifiers: [.command, .option])
        }
        CommandMenu("Item") {
            Button("Edit") { item?.edit() }
                .keyboardShortcut("e")
                .disabled(!open || item == nil)
            Divider()
            Button("Copy Password") { item?.copyPassword?() }
                .keyboardShortcut("c", modifiers: [.command, .shift])
                .disabled(!open || item?.copyPassword == nil)
            Button("Copy Username") { item?.copyUsername?() }
                .keyboardShortcut("c", modifiers: [.command, .option])
                .disabled(!open || item?.copyUsername == nil)
            Button("Copy One-Time Code") { item?.copyCode?() }
                .keyboardShortcut("c", modifiers: [.command, .control])
                .disabled(!open || item?.copyCode == nil)
        }
        CommandMenu("Vault") {
            Button("Search") { search?.run() }
                .keyboardShortcut("f")
                .disabled(!open || search == nil)
            Button("Sync Now") { Task { await vault.syncNow() } }
                .keyboardShortcut("r")
                .disabled(!open || !vault.sync.enabled)
            Divider()
            Button("Lock") { vault.lock() }
                .keyboardShortcut("l")
                .disabled(!open)
        }
    }
}

/// Opens the new-item editor for a kind, or the new SSH key sheet for nil.
struct NewItemAction {
    let run: (Kind?) -> Void
}

struct SearchAction {
    let run: () -> Void
}

/// What the shortcuts can do with the item on screen. A nil action is one
/// the item can't do (a login without a password, for example).
struct ItemActions {
    let edit: () -> Void
    let copyPassword: (() -> Void)?
    let copyUsername: (() -> Void)?
    let copyCode: (() -> Void)?
}

extension FocusedValues {
    @Entry var newItem: NewItemAction?
    @Entry var search: SearchAction?
    @Entry var itemActions: ItemActions?
}
