//! `vaultd`: owns the vault file, holds keys while unlocked, talks to
//! hardware factors and serves paired clients over a Unix socket.

pub mod daemon;
pub use vault_hw as hw;
#[cfg(all(feature = "logind", target_os = "linux"))]
pub mod logind;
pub mod server;
pub mod store;
