//! The vault file parser: anything read from disk or a sync folder.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = vault_core::ParsedVault::parse(data);
});
