//! Recovery code encoding (section 7).

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::Error;
use crate::secret::Key;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RAW_LEN: usize = 36;
const CHARS: usize = 58; // ceil(36 * 8 / 5)
const GROUP: usize = 6;

/// A recovery code as shown to the user once at enrollment. Zeroized on drop.
pub struct RecoveryCode(Zeroizing<String>);

impl RecoveryCode {
    /// The code in display form: Crockford Base32 in groups of six.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn encode(secret: &Key) -> RecoveryCode {
        let mut raw = Zeroizing::new([0u8; RAW_LEN]);
        raw[..32].copy_from_slice(secret.as_bytes());
        raw[32..].copy_from_slice(&checksum(secret.as_bytes()));

        let mut out = Zeroizing::new(String::with_capacity(CHARS + CHARS / GROUP));
        let (mut acc, mut bits, mut n) = (0u16, 0u32, 0usize);
        let mut push = |v: u16, out: &mut String| {
            if n > 0 && n % GROUP == 0 {
                out.push('-');
            }
            out.push(ALPHABET[v as usize] as char);
            n += 1;
        };
        for &b in raw.iter() {
            acc = (acc << 8) | u16::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                push((acc >> bits) & 31, &mut out);
            }
            acc &= (1 << bits) - 1;
        }
        if bits > 0 {
            push((acc << (5 - bits)) & 31, &mut out);
        }
        acc.zeroize();
        RecoveryCode(out)
    }

    /// Parse user input: case-insensitive, ignores hyphens and spaces, accepts
    /// Crockford's `I`/`L` for 1 and `O` for 0. Verifies the checksum.
    pub(crate) fn decode(input: &str) -> Result<Key, Error> {
        let mut raw = Zeroizing::new([0u8; RAW_LEN]);
        let (mut acc, mut bits, mut i, mut chars) = (0u16, 0u32, 0usize, 0usize);
        for c in input.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            let v = value(c).ok_or(Error::BadRecoveryCode)?;
            chars += 1;
            if chars > CHARS {
                return Err(Error::BadRecoveryCode);
            }
            acc = (acc << 5) | v;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                raw[i] = (acc >> bits) as u8;
                i += 1;
                acc &= (1 << bits) - 1;
            }
        }
        // 58 characters carry 290 bits; the last 2 must be zero padding.
        let ok = chars == CHARS && i == RAW_LEN && acc == 0;
        acc.zeroize();
        if !ok {
            return Err(Error::BadRecoveryCode);
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&raw[..32]);
        if checksum(&secret) != raw[32..] {
            secret.zeroize();
            return Err(Error::BadRecoveryCode);
        }
        Ok(Key::from_bytes(secret))
    }
}

fn checksum(secret: &[u8; 32]) -> [u8; 4] {
    let d = Sha256::new()
        .chain_update(b"vault/recovery-check/v1")
        .chain_update(secret)
        .finalize();
    [d[0], d[1], d[2], d[3]]
}

fn value(c: char) -> Option<u16> {
    let c = match c.to_ascii_uppercase() {
        'I' | 'L' => '1',
        'O' => '0',
        c => c,
    };
    ALPHABET
        .iter()
        .position(|&a| a as char == c)
        .map(|p| p as u16)
}
