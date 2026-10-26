//! `vaultd`: owns the vault file, holds keys while unlocked, talks to
//! hardware factors and serves paired clients over a Unix socket or a
//! Windows named pipe.

pub mod approve;
pub mod daemon;
pub use vault_hw as hw;
#[cfg(all(feature = "logind", target_os = "linux"))]
pub mod logind;
pub mod pgp;
#[cfg(all(feature = "secret-service", target_os = "linux"))]
pub mod secret_service;
pub mod server;
pub mod ssh;
pub mod store;
pub mod sync;
#[cfg(windows)]
pub mod winsession;
