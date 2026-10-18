use core::fmt;

/// Errors from parsing, unlocking or editing a vault.
///
/// Variants deliberately carry no data, so no secret can leak through an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not a well-formed vault file (section 2 and 3).
    Malformed,
    /// The file uses a format version or algorithm this reader does not support.
    Unsupported,
    /// The header is not in canonical encoding.
    NonCanonical,
    /// Argon2id parameters are outside the bounds in section 3.1.
    KdfOutOfBounds,
    /// The key-commitment tag did not match: wrong password or hardware factor.
    WrongFactor,
    /// The commitment matched but authenticated decryption failed.
    CorruptSlot,
    /// The header MAC did not verify after unlock (section 4.5).
    HeaderTampered,
    /// The body did not decrypt or decode.
    CorruptBody,
    /// An item did not decrypt.
    CorruptItem,
    /// The slot's factor kind is reserved for a later format version, or the
    /// credential does not fit the slot.
    FactorMismatch,
    /// No slot or item with that ID.
    NotFound,
    /// The operation would leave the vault without a daily-use slot.
    LastSlot,
    /// Too many slots (section 3.1).
    TooManySlots,
    /// The recovery code is malformed or its checksum is wrong.
    BadRecoveryCode,
    /// The OS random number generator failed.
    Random,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::Malformed => "malformed vault file",
            Error::Unsupported => "unsupported format version or algorithm",
            Error::NonCanonical => "non-canonical header encoding",
            Error::KdfOutOfBounds => "KDF parameters out of bounds",
            Error::WrongFactor => "wrong password or factor",
            Error::CorruptSlot => "corrupt keyslot",
            Error::HeaderTampered => "header MAC mismatch",
            Error::CorruptBody => "corrupt body",
            Error::CorruptItem => "corrupt item",
            Error::FactorMismatch => "factor does not fit this slot",
            Error::NotFound => "not found",
            Error::LastSlot => "would remove the last daily-use slot",
            Error::TooManySlots => "too many slots",
            Error::BadRecoveryCode => "bad recovery code",
            Error::Random => "random number generator failed",
        };
        f.write_str(s)
    }
}

impl core::error::Error for Error {}
