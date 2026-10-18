//! Vault file format, key hierarchy and keyslots.
//!
//! This crate is the audit target. It does no I/O and touches no hardware:
//! callers pass in file bytes, passwords and hardware-derived secrets, and get
//! back file bytes. The format is specified in `docs/format.md`; section
//! numbers in comments refer to that document.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod crypto;
mod error;
mod format;
pub mod generator;
pub mod item;
pub mod origin;
mod recovery;
mod rng;
mod secret;
pub mod totp;
mod vault;

pub use error::Error;
pub use format::{
    Argon2Params, FORMAT_VERSION, Factor, KdfCost, KeyslotMeta, MAGIC, ParsedVault, PcrPolicy,
    SlotId,
};
pub use recovery::RecoveryCode;
pub use rng::{OsRandom, SecureRandom};
pub use secret::HwKey;
pub use vault::{ItemId, Unlock, Vault};

#[cfg(test)]
mod tests;
