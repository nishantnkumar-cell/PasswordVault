//! Primitives and the key-commitment construction (section 4.4).

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::Error;
use crate::format::Argon2Params;
use crate::rng::{self, SecureRandom};
use crate::secret::Key;

pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;

/// HKDF-SHA256 with a 32-byte output. `info` is the concatenation of `info_parts`.
pub(crate) fn hkdf(ikm: &[u8], salt: Option<&[u8]>, info_parts: &[&[u8]]) -> Key {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = [0u8; 32];
    hk.expand_multi_info(info_parts, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Key::from_bytes(out)
}

/// HMAC-SHA256 over the concatenation of `parts`.
pub(crate) fn hmac(key: &Key, parts: &[&[u8]]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

pub(crate) fn hmac_verify(key: &Key, parts: &[&[u8]], expected: &[u8; 32]) -> bool {
    hmac(key, parts).ct_eq(expected).into()
}

/// Argon2id with parameters already checked against section 3.1.
pub(crate) fn argon2id(password: &[u8], p: &Argon2Params) -> Result<Key, Error> {
    p.check_bounds()?;
    let params = Params::new(p.m_kib, p.t, p.p, Some(32)).map_err(|_| Error::KdfOutOfBounds)?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, &p.salt, out.as_mut())
        .map_err(|_| Error::KdfOutOfBounds)?;
    Ok(Key::from_bytes(*out))
}

fn enc_key(k: &Key) -> Key {
    hkdf(k.as_bytes(), None, &[b"vault/enc/v1"])
}

fn commit_key(k: &Key) -> Key {
    hkdf(k.as_bytes(), None, &[b"vault/commit/v1"])
}

/// A record encrypted under the commitment rule: AEAD under `K_enc`, plus
/// `HMAC(K_commit, nonce)`.
pub(crate) struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub commit: [u8; 32],
    pub ciphertext: Vec<u8>,
}

pub(crate) fn seal(
    rng: &mut dyn SecureRandom,
    key: &Key,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Sealed, Error> {
    let nonce: [u8; NONCE_LEN] = rng::array(rng)?;
    seal_with_nonce(key, nonce, aad, plaintext)
}

pub(crate) fn seal_with_nonce(
    key: &Key,
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Sealed, Error> {
    let commit = hmac(&commit_key(key), &[&nonce]);
    let cipher = XChaCha20Poly1305::new(&(*enc_key(key).as_bytes()).into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Malformed)?;
    Ok(Sealed {
        nonce,
        commit,
        ciphertext,
    })
}

/// Why opening a sealed record failed.
pub(crate) enum OpenError {
    /// The commitment did not match: this is not the record's key.
    WrongKey,
    /// The key is right but the ciphertext or AAD was altered.
    Corrupt,
}

pub(crate) fn open(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    commit: &[u8; 32],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    if !hmac_verify(&commit_key(key), &[nonce], commit) {
        return Err(OpenError::WrongKey);
    }
    let cipher = XChaCha20Poly1305::new(&(*enc_key(key).as_bytes()).into());
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| OpenError::Corrupt)
}
