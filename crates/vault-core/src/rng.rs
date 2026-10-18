use crate::Error;

/// Source of cryptographically secure random bytes.
///
/// Production code uses [`OsRandom`]. Tests may supply a deterministic source
/// to produce reproducible test vectors.
pub trait SecureRandom {
    /// Fill `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

/// The operating system's CSPRNG, via `getrandom`.
pub struct OsRandom;

impl SecureRandom for OsRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(buf).map_err(|_| Error::Random)
    }
}

pub(crate) fn array<const N: usize>(rng: &mut dyn SecureRandom) -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    rng.fill(&mut out)?;
    Ok(out)
}
