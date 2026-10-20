//! Check that Windows Hello can approve a quick unlock on this computer:
//!
//!     cargo run -p vault-hw --example hello-check
//!
//! It asks once for your face, fingerprint or Windows PIN. Nothing is stored.

#[cfg(windows)]
fn main() {
    use vault_hw::Presence;
    let hello = vault_hw::hello::WinHello;
    if let Err(e) = hello.check_available() {
        eprintln!("FAIL: {e}");
        std::process::exit(1);
    }
    println!("Windows Hello is set up. Confirm it's you in the Windows Security window...");
    match hello.verify("Secret Vault: test Windows Hello") {
        Ok(()) => println!("\nPASS: Windows Hello can approve a quick unlock here."),
        Err(e) => {
            eprintln!("FAIL: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Windows Hello is Windows only.");
    std::process::exit(1);
}
