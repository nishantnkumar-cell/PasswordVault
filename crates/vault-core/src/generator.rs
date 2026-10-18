//! Password and passphrase generation from the OS CSPRNG.

use zeroize::Zeroizing;

use crate::Error;
use crate::rng::SecureRandom;

/// Character classes for [`generate_password`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Charset {
    /// a-z
    pub lower: bool,
    /// A-Z
    pub upper: bool,
    /// 0-9
    pub digits: bool,
    /// Printable ASCII symbols.
    pub symbols: bool,
    /// Drop look-alike characters (0 O o 1 l I).
    pub avoid_ambiguous: bool,
}

impl Default for Charset {
    fn default() -> Self {
        Charset {
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
const AMBIGUOUS: &str = "0Oo1lI";

/// Uniform integer in `0..n` by rejection sampling (no modulo bias).
pub(crate) fn uniform(rng: &mut dyn SecureRandom, n: u32) -> Result<u32, Error> {
    assert!(n > 0);
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let mut b = [0u8; 4];
        rng.fill(&mut b)?;
        let v = u32::from_le_bytes(b);
        if v < zone {
            return Ok(v % n);
        }
    }
}

/// A random password of `len` characters with at least one character from
/// each selected class.
pub fn generate_password(
    rng: &mut dyn SecureRandom,
    len: usize,
    cs: Charset,
) -> Result<Zeroizing<String>, Error> {
    let classes: Vec<Vec<char>> = [
        (cs.lower, ('a'..='z').collect::<String>()),
        (cs.upper, ('A'..='Z').collect::<String>()),
        (cs.digits, ('0'..='9').collect::<String>()),
        (cs.symbols, SYMBOLS.to_owned()),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, s)| {
        s.chars()
            .filter(|c| !(cs.avoid_ambiguous && AMBIGUOUS.contains(*c)))
            .collect()
    })
    .collect();
    if classes.is_empty() || len < classes.len() || len > 1024 {
        return Err(Error::Malformed);
    }
    let all: Vec<char> = classes.iter().flatten().copied().collect();
    loop {
        let mut out = Zeroizing::new(String::with_capacity(len));
        for _ in 0..len {
            out.push(all[uniform(rng, all.len() as u32)? as usize]);
        }
        // Resample rather than patch, which keeps the distribution uniform
        // over passwords that contain every class.
        if classes
            .iter()
            .all(|c| out.chars().any(|ch| c.contains(&ch)))
        {
            return Ok(out);
        }
    }
}

/// A passphrase of `words` words from `wordlist`, joined by `sep`.
pub fn generate_passphrase(
    rng: &mut dyn SecureRandom,
    wordlist: &[&str],
    words: usize,
    sep: &str,
) -> Result<Zeroizing<String>, Error> {
    if wordlist.len() < 2 || words == 0 || words > 64 {
        return Err(Error::Malformed);
    }
    let mut out = Zeroizing::new(String::new());
    for i in 0..words {
        if i > 0 {
            out.push_str(sep);
        }
        out.push_str(wordlist[uniform(rng, wordlist.len() as u32)? as usize]);
    }
    Ok(out)
}
