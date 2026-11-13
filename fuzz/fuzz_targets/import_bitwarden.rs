//! A Bitwarden JSON export chosen by the user.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = vault_import::bitwarden_json(text, 0);
    }
});
