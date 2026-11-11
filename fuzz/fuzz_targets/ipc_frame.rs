//! Frames sent to vaultd over its socket, and the replies read by clients.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = vault_ipc::read_frame::<_, vault_ipc::Envelope>(&mut &data[..]);
    let _ = vault_ipc::read_frame::<_, vault_ipc::Response>(&mut &data[..]);
});
