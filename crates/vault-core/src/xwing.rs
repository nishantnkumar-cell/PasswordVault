//! X-Wing, the hybrid KEM ML-KEM-768 + X25519 (draft-connolly-cfrg-xwing-kem),
//! used to wrap a shared collection's vault key for each member (format.md 3.2).

use kem::Decapsulate;
use ml_kem::{B32, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768, array::Array};
use sha3::{
    Digest, Sha3_256, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::Error;
use crate::rng::{self, SecureRandom};

/// Length of an X-Wing public (encapsulation) key.
pub const PUBLIC_KEY_LEN: usize = 1216;
/// Length of an X-Wing ciphertext.
pub const CIPHERTEXT_LEN: usize = 1120;
const MLKEM_PK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;
const LABEL: &[u8; 6] = b"\\.//^\\";

type DecapKey = <MlKem768 as KemCore>::DecapsulationKey;
type EncapKey = <MlKem768 as KemCore>::EncapsulationKey;

/// An X-Wing secret key: a 32-byte seed, from which both halves are derived.
#[derive(Clone)]
pub struct XWingSecret {
    seed: Zeroizing<[u8; 32]>,
}

struct Expanded {
    dk: DecapKey,
    ek: EncapKey,
    sk_x: StaticSecret,
    pk_x: PublicKey,
}

impl XWingSecret {
    /// A new random secret key.
    pub fn generate(rng: &mut dyn SecureRandom) -> Result<XWingSecret, Error> {
        Ok(XWingSecret::from_seed(rng::array(rng)?))
    }

    /// The secret key with this seed.
    pub fn from_seed(seed: [u8; 32]) -> XWingSecret {
        XWingSecret {
            seed: Zeroizing::new(seed),
        }
    }

    /// The seed, for storing the key.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    fn expand(&self) -> Expanded {
        let mut xof = Shake256::default();
        xof.update(self.seed.as_ref());
        let mut out = Zeroizing::new([0u8; 96]);
        xof.finalize_xof().read(out.as_mut());
        let d = B32::try_from(&out[0..32]).expect("32 bytes");
        let z = B32::try_from(&out[32..64]).expect("32 bytes");
        let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&out[64..96]);
        let sk_x = StaticSecret::from(sk);
        sk.zeroize();
        let pk_x = PublicKey::from(&sk_x);
        Expanded { dk, ek, sk_x, pk_x }
    }

    /// The matching public key, `pk_M || pk_X`.
    pub fn public_key(&self) -> Vec<u8> {
        let e = self.expand();
        let mut pk = e.ek.as_bytes().to_vec();
        pk.extend_from_slice(e.pk_x.as_bytes());
        pk
    }

    /// The shared secret in `ct`, which must be `CIPHERTEXT_LEN` bytes.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
        if ct.len() != CIPHERTEXT_LEN {
            return Err(Error::Malformed);
        }
        let e = self.expand();
        let ct_m = Array::try_from(&ct[..MLKEM_CT_LEN]).map_err(|_| Error::Malformed)?;
        let ct_x: [u8; 32] = ct[MLKEM_CT_LEN..].try_into().expect("32 bytes");
        let ss_m = e.dk.decapsulate(&ct_m).map_err(|_| Error::Malformed)?;
        let ss_x = e.sk_x.diffie_hellman(&PublicKey::from(ct_x));
        Ok(combine(&ss_m, ss_x.as_bytes(), &ct_x, e.pk_x.as_bytes()))
    }
}

/// Check that `pk` is a well-formed X-Wing public key.
pub fn check_public_key(pk: &[u8]) -> Result<(), Error> {
    if pk.len() != PUBLIC_KEY_LEN {
        return Err(Error::Malformed);
    }
    let enc = Array::try_from(&pk[..MLKEM_PK_LEN]).map_err(|_| Error::Malformed)?;
    // FIPS 203 7.2 modulus check: decoding and re-encoding must give the same bytes.
    if EncapKey::from_bytes(&enc).as_bytes() != enc {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// A fresh shared secret for `pk` and its ciphertext.
pub fn encapsulate(
    pk: &[u8],
    rng: &mut dyn SecureRandom,
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), Error> {
    let mut eseed = Zeroizing::new([0u8; 64]);
    rng.fill(eseed.as_mut())?;
    encapsulate_derand(pk, &eseed)
}

fn encapsulate_derand(
    pk: &[u8],
    eseed: &[u8; 64],
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), Error> {
    check_public_key(pk)?;
    let ek = EncapKey::from_bytes(&Array::try_from(&pk[..MLKEM_PK_LEN]).expect("checked"));
    let pk_x: [u8; 32] = pk[MLKEM_PK_LEN..].try_into().expect("checked");
    let m = B32::try_from(&eseed[..32]).expect("32 bytes");
    let (ct_m, ss_m) = ek
        .encapsulate_deterministic(&m)
        .map_err(|_| Error::Malformed)?;
    let mut ek_x = [0u8; 32];
    ek_x.copy_from_slice(&eseed[32..]);
    let ek_x = StaticSecret::from(ek_x);
    let ct_x = PublicKey::from(&ek_x);
    let ss_x = ek_x.diffie_hellman(&PublicKey::from(pk_x));
    let ss = combine(&ss_m, ss_x.as_bytes(), ct_x.as_bytes(), &pk_x);
    let mut ct = ct_m.to_vec();
    ct.extend_from_slice(ct_x.as_bytes());
    Ok((ct, ss))
}

fn combine(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, LABEL);
    Zeroizing::new(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    /// The first test vector of draft-connolly-cfrg-xwing-kem-11, appendix C.
    #[test]
    fn draft_test_vector() {
        let seed: [u8; 32] =
            hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
                .try_into()
                .unwrap();
        let eseed: [u8; 64] = hex(concat!(
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2",
            "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2"
        ))
        .try_into()
        .unwrap();
        let sk = XWingSecret::from_seed(seed);
        let pk = sk.public_key();
        assert_eq!(pk.len(), PUBLIC_KEY_LEN);
        assert_eq!(pk[..16], hex("e2236b35a8c24b39b10aa1323a96a919")[..]);
        let (ct, ss) = encapsulate_derand(&pk, &eseed).unwrap();
        assert_eq!(ct.len(), CIPHERTEXT_LEN);
        assert_eq!(ct[..16], hex("b83aa828d4d62b9a83ceffe1d3d3bb1e")[..]);
        let want = hex("d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384");
        assert_eq!(ss[..], want[..]);
        assert_eq!(sk.decapsulate(&ct).unwrap()[..], want[..]);
    }

    #[test]
    fn wrong_key_gets_a_different_secret() {
        let a = XWingSecret::from_seed([1; 32]);
        let b = XWingSecret::from_seed([2; 32]);
        let (ct, ss) = encapsulate_derand(&a.public_key(), &[7; 64]).unwrap();
        assert_ne!(b.decapsulate(&ct).unwrap()[..], ss[..]);
        assert!(check_public_key(&[0; 10]).is_err());
        assert!(a.decapsulate(&ct[1..]).is_err());
    }
}
