//! `vaultd`: owns the vault file, holds keys while unlocked, talks to
//! hardware factors and serves paired clients over a Unix socket or a
//! Windows named pipe.

pub mod approve;
pub mod daemon;
pub use vault_hw as hw;
#[cfg(all(feature = "logind", target_os = "linux"))]
pub mod logind;
pub mod pgp;
pub mod server;
pub mod ssh;
pub mod store;
#[cfg(windows)]
pub mod winsession;
