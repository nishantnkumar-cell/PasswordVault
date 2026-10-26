//! Check that Windows Hello, or Touch ID on macOS, can approve a quick unlock
//! on this computer:
//!
//!     cargo run -p vault-hw --example hello-check
//!
//! It asks once for your face, fingerprint or Windows PIN (on a Mac: Touch ID
//! or your login password). Nothing is stored.

#[cfg(any(windows, target_os = "macos"))]
fn main() {
    use vault_hw::{PRESENCE_NAME, Presence};
    #[cfg(windows)]
    let check = vault_hw::hello::WinHello;
    #[cfg(target_os = "macos")]
    let check = vault_hw::touchid::TouchId;
    if let Err(e) = check.check_available() {
        eprintln!("FAIL: {e}");
        std::process::exit(1);
    }
    println!("{PRESENCE_NAME} is set up. Confirm it's you in the window that opens...");
    match check.verify(&format!("Test {PRESENCE_NAME} for Secret Vault")) {
        Ok(()) => println!("\nPASS: {PRESENCE_NAME} can approve a quick unlock here."),
        Err(e) => {
            eprintln!("FAIL: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn main() {
    eprintln!("Quick unlock uses Windows Hello or Touch ID; Linux has neither.");
    std::process::exit(1);
}
