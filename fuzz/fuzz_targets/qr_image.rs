//! A picture of a QR code, for "Add Code" from an image.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = vault_import::qr::otpauth_from_image(data);
});
