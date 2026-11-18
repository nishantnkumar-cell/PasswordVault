//! A person's sharing identity (format.md 3.2): one 32-byte seed, from which
//! an X-Wing key (to receive a shared collection's key) and a hybrid
//! ML-DSA-65 + Ed25519 signing key (to sign a collection's member list) are
//! derived. The seed lives in the person's own vault, never in a shared one.

use ed25519_dalek::{Signer, Verifier};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, KeyGen, MlDsa65, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;
use crate::crypto;
use crate::format;
use crate::rng::{self, SecureRandom};
use crate::xwing::{self, XWingSecret};

/// ML-DSA-65 verifying key length.
const MLDSA_VK_LEN: usize = 1952;
/// ML-DSA-65 signature length.
const MLDSA_SIG_LEN: usize = 3309;
/// Length of a hybrid signature: ML-DSA-65 then Ed25519.
pub const SIGNATURE_LEN: usize = MLDSA_SIG_LEN + 64;

/// A person's secret sharing identity.
#[derive(Clone)]
pub struct Identity {
    seed: Zeroizing<[u8; 32]>,
}

/// The public half of an [`Identity`], which others need to share with that
/// person and to check what they signed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    /// X-Wing encapsulation key, 1216 bytes.
    pub kem: Vec<u8>,
    /// ML-DSA-65 verifying key, 1952 bytes.
    pub mldsa: Vec<u8>,
    /// Ed25519 verifying key.
    pub ed25519: [u8; 32],
}

impl Identity {
    /// A new random identity.
    pub fn generate(rng: &mut dyn SecureRandom) -> Result<Identity, Error> {
        Ok(Identity::from_seed(rng::array(rng)?))
    }

    /// The identity with this seed.
    pub fn from_seed(seed: [u8; 32]) -> Identity {
        Identity {
            seed: Zeroizing::new(seed),
        }
    }

    /// The seed, for keeping the identity in the person's own vault.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    fn part(&self, label: &[u8]) -> Zeroizing<[u8; 32]> {
        let k = crypto::hkdf(self.seed.as_ref(), None, &[b"vault/identity/v1/", label]);
        Zeroizing::new(*k.as_bytes())
    }

    pub(crate) fn kem(&self) -> XWingSecret {
        XWingSecret::from_seed(*self.part(b"kem"))
    }

    fn mldsa(&self) -> ml_dsa::KeyPair<MlDsa65> {
        let xi = self.part(b"mldsa");
        MlDsa65::key_gen_internal(&ml_dsa::B32::from(*xi))
    }

    fn ed25519(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.part(b"ed25519"))
    }

    /// The public half.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            kem: self.kem().public_key(),
            mldsa: self.mldsa().verifying_key().encode().to_vec(),
            ed25519: self.ed25519().verifying_key().to_bytes(),
        }
    }

    /// Sign `msg` for `context` with both keys. The signature only verifies
    /// if both halves do.
    pub(crate) fn sign(&self, context: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        let m = signed_message(context, msg);
        let pq = self
            .mldsa()
            .signing_key()
            .sign_deterministic(&m, context)
            .map_err(|_| Error::Malformed)?;
        let mut sig = pq.encode().to_vec();
        sig.extend_from_slice(&self.ed25519().sign(&m).to_bytes());
        Ok(sig)
    }
}

fn signed_message(context: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + context.len() + msg.len());
    m.extend_from_slice(b"vault/signed/v1");
    m.extend_from_slice(&(context.len() as u16).to_le_bytes());
    m.extend_from_slice(context);
    m.extend_from_slice(msg);
    m
}

impl PublicIdentity {
    /// Check the key lengths and that the X-Wing key is well formed.
    pub fn check(&self) -> Result<(), Error> {
        xwing::check_public_key(&self.kem)?;
        if self.mldsa.len() != MLDSA_VK_LEN {
            return Err(Error::Malformed);
        }
        ed25519_dalek::VerifyingKey::from_bytes(&self.ed25519).map_err(|_| Error::Malformed)?;
        Ok(())
    }

    /// SHA-256 over the encoded public identity: what slots and member lists
    /// name a person by.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"vault/identity-fp/v1");
        h.update(format::encode(self));
        h.finalize().into()
    }

    /// Six groups of four digits that two people read to each other to be
    /// sure they have each other's real key (like a safety number).
    pub fn safety_code(&self) -> String {
        safety_code(&self.fingerprint())
    }

    /// The encoded public identity.
    pub fn to_bytes(&self) -> Vec<u8> {
        format::encode(self)
    }

    /// Decode and check a public identity.
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicIdentity, Error> {
        let p: PublicIdentity = format::decode_canonical(bytes)?;
        p.check()?;
        Ok(p)
    }

    /// Verify a signature made with [`Identity::sign`] for `context`.
    pub(crate) fn verify(&self, context: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != SIGNATURE_LEN || self.mldsa.len() != MLDSA_VK_LEN {
            return false;
        }
        let m = signed_message(context, msg);
        let Ok(vk_bytes) = EncodedVerifyingKey::<MlDsa65>::try_from(self.mldsa.as_slice()) else {
            return false;
        };
        let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&vk_bytes);
        let Ok(sig_pq) = EncodedSignature::<MlDsa65>::try_from(&sig[..MLDSA_SIG_LEN]) else {
            return false;
        };
        let Some(sig_pq) = Signature::<MlDsa65>::decode(&sig_pq) else {
            return false;
        };
        if !vk.verify_with_context(&m, context, &sig_pq) {
            return false;
        }
        let Ok(ed) = ed25519_dalek::VerifyingKey::from_bytes(&self.ed25519) else {
            return false;
        };
        let ed_sig = ed25519_dalek::Signature::from_bytes(
            sig[MLDSA_SIG_LEN..].try_into().expect("64 bytes"),
        );
        ed.verify_strict(&m, &ed_sig).is_ok() && ed.verify(&m, &ed_sig).is_ok()
    }
}

/// Six groups of four digits from a fingerprint.
pub fn safety_code(fp: &[u8; 32]) -> String {
    (0..6)
        .map(|i| {
            let n = u32::from_le_bytes(fp[i * 4..i * 4 + 4].try_into().unwrap()) % 10_000;
            format!("{n:04}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_tamper() {
        let a = Identity::from_seed([3; 32]);
        let b = Identity::from_seed([4; 32]);
        let pa = a.public();
        pa.check().unwrap();
        assert_eq!(PublicIdentity::from_bytes(&pa.to_bytes()).unwrap(), pa);
        let sig = a.sign(b"test", b"hello").unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(pa.verify(b"test", b"hello", &sig));
        assert!(!pa.verify(b"other", b"hello", &sig));
        assert!(!pa.verify(b"test", b"hellO", &sig));
        assert!(!b.public().verify(b"test", b"hello", &sig));
        // Both halves must verify.
        let mut half = sig.clone();
        half[SIGNATURE_LEN - 1] ^= 1;
        assert!(!pa.verify(b"test", b"hello", &half));
        let mut half = sig.clone();
        half[10] ^= 1;
        assert!(!pa.verify(b"test", b"hello", &half));
        assert_ne!(pa.fingerprint(), b.public().fingerprint());
        assert_eq!(pa.safety_code().len(), 6 * 4 + 5);
    }
}
