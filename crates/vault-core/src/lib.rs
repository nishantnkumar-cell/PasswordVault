//! Vault file format, key hierarchy and keyslots.
//!
//! This crate is the audit target. It does no I/O and touches no hardware:
//! callers pass in file bytes, passwords and hardware-derived secrets, and get
//! back file bytes. The format is specified in `docs/format.md`; section
//! numbers in comments refer to that document.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod clock;
pub mod collection;
mod crypto;
mod error;
mod format;
pub mod generator;
pub mod identity;
pub mod item;
mod merge;
pub mod origin;
mod recovery;
mod rng;
mod secret;
pub mod totp;
mod vault;
pub mod xwing;

pub use clock::DeviceId;
pub use error::Error;
pub use format::{
    Argon2Params, FORMAT_VERSION, Factor, KDF_MAX_M_KIB, KdfCost, KeyslotMeta, MAGIC, ParsedVault,
    PcrPolicy, SlotId,
};
pub use merge::{MergeReport, Resolve};
pub use recovery::RecoveryCode;
pub use rng::{OsRandom, SecureRandom};
pub use secret::HwKey;
pub use vault::{ItemId, ParkedKey, Unlock, Vault};

#[cfg(test)]
mod tests;
