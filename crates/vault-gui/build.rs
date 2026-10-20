//! Windows: embed the app icon in `vault-gui.exe` and `vault-prompt.exe`, so Explorer,
//! the Start menu shortcut and the taskbar show it. Does nothing on other systems.

fn main() {
    println!("cargo:rerun-if-changed=vault-gui.rc");
    println!("cargo:rerun-if-changed=../../contrib/icons/secret-vault.ico");
    embed_resource::compile("vault-gui.rc", embed_resource::NONE)
        .manifest_optional()
        .unwrap();
}
