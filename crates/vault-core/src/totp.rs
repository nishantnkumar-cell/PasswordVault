//! RFC 6238 time-based one-time passwords.

use hmac::{EagerHash, Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

/// HMAC hash used by a TOTP seed.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    /// SHA-1, the default almost every site uses.
    #[default]
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

/// A TOTP seed and its parameters. Zeroized on drop.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TotpConfig {
    /// Raw shared secret (decoded from Base32).
    pub secret: Vec<u8>,
    /// Number of digits, 6 to 8.
    pub digits: u8,
    /// Step in seconds, usually 30.
    pub period: u32,
    /// Hash algorithm.
    #[zeroize(skip)]
    pub algorithm: TotpAlgorithm,
}

impl TotpConfig {
    /// Parse a Base32 secret as shown by sites (spaces and padding ignored)
    /// with the common defaults: 6 digits, 30 seconds, SHA-1.
    pub fn from_base32(secret: &str) -> Result<TotpConfig, Error> {
        let mut cleaned: String = secret
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let decoded = data_encoding::BASE32_NOPAD.decode(cleaned.as_bytes());
        cleaned.zeroize();
        let secret = decoded.map_err(|_| Error::Malformed)?;
        if secret.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(TotpConfig {
            secret,
            digits: 6,
            period: 30,
            algorithm: TotpAlgorithm::Sha1,
        })
    }

    /// Parse an `otpauth://totp/...` URI or, failing that, a bare Base32 secret.
    pub fn parse(s: &str) -> Result<TotpConfig, Error> {
        let s = s.trim();
        if !s.to_ascii_lowercase().starts_with("otpauth://") {
            return TotpConfig::from_base32(s);
        }
        let u = url::Url::parse(s).map_err(|_| Error::Malformed)?;
        if u.host_str() != Some("totp") {
            return Err(Error::Malformed);
        }
        let mut cfg: Option<TotpConfig> = None;
        let (mut digits, mut period, mut algorithm) = (6u8, 30u32, TotpAlgorithm::Sha1);
        for (k, v) in u.query_pairs() {
            match k.as_ref() {
                "secret" => cfg = Some(TotpConfig::from_base32(&v)?),
                "digits" => digits = v.parse().map_err(|_| Error::Malformed)?,
                "period" => period = v.parse().map_err(|_| Error::Malformed)?,
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => TotpAlgorithm::Sha1,
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        _ => return Err(Error::Malformed),
                    }
                }
                _ => {}
            }
        }
        let mut cfg = cfg.ok_or(Error::Malformed)?;
        if !(6..=8).contains(&digits) || period == 0 {
            return Err(Error::Malformed);
        }
        (cfg.digits, cfg.period, cfg.algorithm) = (digits, period, algorithm);
        Ok(cfg)
    }

    /// The code for Unix time `now` (seconds).
    pub fn code_at(&self, now: u64) -> Result<String, Error> {
        if !(6..=8).contains(&self.digits) || self.period == 0 {
            return Err(Error::Malformed);
        }
        let counter = (now / u64::from(self.period)).to_be_bytes();
        let mac = match self.algorithm {
            TotpAlgorithm::Sha1 => hmac_bytes::<sha1::Sha1>(&self.secret, &counter),
            TotpAlgorithm::Sha256 => hmac_bytes::<sha2::Sha256>(&self.secret, &counter),
            TotpAlgorithm::Sha512 => hmac_bytes::<sha2::Sha512>(&self.secret, &counter),
        };
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;
        let bin = u32::from_be_bytes([
            mac[offset] & 0x7f,
            mac[offset + 1],
            mac[offset + 2],
            mac[offset + 3],
        ]);
        let modulus = 10u32.pow(u32::from(self.digits));
        Ok(format!(
            "{:0width$}",
            bin % modulus,
            width = self.digits as usize
        ))
    }

    /// Seconds until the code for `now` expires.
    pub fn remaining(&self, now: u64) -> u64 {
        let p = u64::from(self.period.max(1));
        p - now % p
    }
}

fn hmac_bytes<D: EagerHash>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<D> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}
