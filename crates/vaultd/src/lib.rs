//! `vaultd`: owns the vault file, holds keys while unlocked, talks to
//! hardware factors and serves paired clients over a Unix socket.

pub mod daemon;
pub mod hw;
pub mod server;
pub mod store;
