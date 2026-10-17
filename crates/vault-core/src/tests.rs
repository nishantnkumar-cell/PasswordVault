//! Unit tests, including negative vectors that need access to internals.

use sha2::{Digest, Sha256};

use crate::format::{self, Header, ParsedVault, SealedBody};
use crate::*;

/// Deterministic generator for reproducible test vectors: SHA-256 in counter mode.
pub(crate) struct TestRng(u64);

impl SecureRandom for TestRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        for chunk in buf.chunks_mut(32) {
            let d = Sha256::new()
                .chain_update(b"vault-core test rng")
                .chain_update(self.0.to_le_bytes())
                .finalize();
            self.0 += 1;
            chunk.copy_from_slice(&d[..chunk.len()]);
        }
        Ok(())
    }
}

const PW: &str = "correct horse battery staple";
const COST: KdfCost = KdfCost::MINIMUM;

fn fido2(uv: bool) -> Factor {
    Factor::PasswordFido2 {
        credential_id: vec![7; 64],
        rp_id: "vault.example".into(),
        prf_input: [9; 32],
        require_uv: uv,
    }
}

struct Fixture {
    bytes: Vec<u8>,
    pw_slot: SlotId,
    fido_slot: SlotId,
    rec_slot: SlotId,
    code: String,
    items: [ItemId; 2],
}

fn fixture(rng: &mut TestRng) -> Fixture {
    let mut v = Vault::new(rng).unwrap();
    let pw_slot = v
        .add_password_slot(rng, Factor::PasswordOnly, COST, PW, None, "password")
        .unwrap();
    let hw = HwKey::new([0xA5; 32]);
    let fido_slot = v
        .add_password_slot(rng, fido2(true), COST, PW, Some(&hw), "blue key")
        .unwrap();
    let (rec_slot, code) = v.add_recovery_slot(rng, "paper").unwrap();
    let a = v.new_item_id(rng).unwrap();
    let b = v.new_item_id(rng).unwrap();
    v.put_item(rng, &a, b"item a").unwrap();
    v.put_item(rng, &b, b"item b").unwrap();
    Fixture {
        bytes: v.to_bytes(rng).unwrap(),
        pw_slot,
        fido_slot,
        rec_slot,
        code: code.as_str().to_owned(),
        items: [a, b],
    }
}

fn pw(p: &str) -> Unlock<'_> {
    Unlock::Password {
        password: p,
        hw_key: None,
    }
}

fn unlock_pw(bytes: &[u8], slot: &SlotId) -> Result<Vault, Error> {
    ParsedVault::parse(bytes)?.unlock(slot, &pw(PW))
}

/// Rebuild a file from parts, recomputing nothing.
fn rebuild(header: &Header, mac: &[u8; 32], body: &SealedBody) -> Vec<u8> {
    format::assemble(&format::encode(header), mac, &format::encode(body))
}

#[test]
fn roundtrip_all_slot_kinds() {
    let f = fixture(&mut TestRng(0));
    let p = ParsedVault::parse(&f.bytes).unwrap();
    assert_eq!(p.slots().count(), 3);

    let v = p.unlock(&f.pw_slot, &pw(PW)).unwrap();
    assert_eq!(v.generation(), 1);
    assert_eq!(&**v.get_item(&f.items[0]).unwrap(), b"item a");
    assert_eq!(&**v.get_item(&f.items[1]).unwrap(), b"item b");
    assert_eq!(v.slot_label(&f.fido_slot), Some("blue key"));

    let hw = HwKey::new([0xA5; 32]);
    p.unlock(
        &f.fido_slot,
        &Unlock::Password {
            password: PW,
            hw_key: Some(&hw),
        },
    )
    .unwrap();
    p.unlock(&f.rec_slot, &Unlock::Recovery { code: &f.code })
        .unwrap();
}

#[test]
fn golden_file_is_stable() {
    // Pins the exact encoding. If this changes, the on-disk format changed:
    // bump format_version or fix the regression.
    let f = fixture(&mut TestRng(0));
    let digest = Sha256::digest(&f.bytes);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(f.bytes.len(), GOLDEN_LEN, "golden length changed");
    assert_eq!(hex, GOLDEN_SHA256, "golden digest changed");
}

const GOLDEN_LEN: usize = 4890;
const GOLDEN_SHA256: &str = "f11dfe11ed1de2b1a7c294b6db5fa271db8b85b01dbc0346365cc213723a0732";

#[test]
fn wrong_password_is_wrong_factor() {
    let f = fixture(&mut TestRng(0));
    let p = ParsedVault::parse(&f.bytes).unwrap();
    assert_eq!(
        p.unlock(&f.pw_slot, &pw("wrong")).err(),
        Some(Error::WrongFactor)
    );
}

#[test]
fn fido2_wrong_secret_or_uv_mode_fails() {
    let f = fixture(&mut TestRng(0));
    let p = ParsedVault::parse(&f.bytes).unwrap();
    // Without UV the authenticator returns a different secret.
    let other = HwKey::new([0x5A; 32]);
    assert_eq!(
        p.unlock(
            &f.fido_slot,
            &Unlock::Password {
                password: PW,
                hw_key: Some(&other)
            }
        )
        .err(),
        Some(Error::WrongFactor)
    );
    assert_eq!(
        p.unlock(&f.fido_slot, &pw(PW)).err(),
        Some(Error::FactorMismatch)
    );
    let hw = HwKey::new([0xA5; 32]);
    assert_eq!(
        p.unlock(
            &f.pw_slot,
            &Unlock::Password {
                password: PW,
                hw_key: Some(&hw)
            }
        )
        .err(),
        Some(Error::FactorMismatch)
    );
}

#[test]
fn flipping_require_uv_in_header_breaks_the_slot() {
    let f = fixture(&mut TestRng(0));
    let p = ParsedVault::parse(&f.bytes).unwrap();
    let mut header = Header {
        vault_id: p.header.vault_id,
        aead: 1,
        slots: p.header.slots.clone(),
    };
    for s in &mut header.slots {
        if let Factor::PasswordFido2 { require_uv, .. } = &mut s.meta.factor {
            *require_uv = false;
        }
    }
    let bytes = rebuild(&header, &p.header_mac, &p.body);
    let hw = HwKey::new([0xA5; 32]);
    let r = ParsedVault::parse(&bytes).unwrap().unlock(
        &f.fido_slot,
        &Unlock::Password {
            password: PW,
            hw_key: Some(&hw),
        },
    );
    assert_eq!(r.err(), Some(Error::CorruptSlot));
}

#[test]
fn injected_slot_is_detected_by_header_mac() {
    let f = fixture(&mut TestRng(0));
    let other = fixture(&mut TestRng(1000));
    let p = ParsedVault::parse(&f.bytes).unwrap();
    let o = ParsedVault::parse(&other.bytes).unwrap();
    let mut header = Header {
        vault_id: p.header.vault_id,
        aead: 1,
        slots: p.header.slots.clone(),
    };
    header.slots.push(o.header.slots[0].clone());
    let bytes = rebuild(&header, &p.header_mac, &p.body);
    assert_eq!(
        unlock_pw(&bytes, &f.pw_slot).err(),
        Some(Error::HeaderTampered)
    );
}

#[test]
fn removed_slot_restored_is_detected_by_header_mac() {
    let mut rng = TestRng(0);
    let f = fixture(&mut rng);
    let mut v = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    v.remove_slot(&f.fido_slot).unwrap();
    let newer = v.to_bytes(&mut rng).unwrap();
    // Splice the old slot list onto the newer file.
    let old = ParsedVault::parse(&f.bytes).unwrap();
    let new = ParsedVault::parse(&newer).unwrap();
    let header = Header {
        vault_id: old.header.vault_id,
        aead: 1,
        slots: old.header.slots.clone(),
    };
    let bytes = rebuild(&header, &new.header_mac, &new.body);
    assert_eq!(
        unlock_pw(&bytes, &f.pw_slot).err(),
        Some(Error::HeaderTampered)
    );
}

#[test]
fn body_from_another_write_is_rejected() {
    let mut rng = TestRng(0);
    let f = fixture(&mut rng);
    let mut v = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    v.add_password_slot(&mut rng, Factor::PasswordOnly, COST, "second", None, "")
        .unwrap();
    let newer = v.to_bytes(&mut rng).unwrap();
    let old = ParsedVault::parse(&f.bytes).unwrap();
    let new = ParsedVault::parse(&newer).unwrap();
    let header = Header {
        vault_id: new.header.vault_id,
        aead: 1,
        slots: new.header.slots.clone(),
    };
    let bytes = rebuild(&header, &new.header_mac, &old.body);
    assert_eq!(
        unlock_pw(&bytes, &f.pw_slot).err(),
        Some(Error::CorruptBody)
    );
}

#[test]
fn kdf_bounds_are_enforced_before_running_argon2() {
    let f = fixture(&mut TestRng(0));
    let p = ParsedVault::parse(&f.bytes).unwrap();
    for (m, t, pp) in [
        (u32::MAX, 1, 1),
        (65_536, 1_000_000, 1),
        (65_536, 1, 255),
        (1024, 1, 1),
    ] {
        let mut header = Header {
            vault_id: p.header.vault_id,
            aead: 1,
            slots: p.header.slots.clone(),
        };
        let kdf = header.slots[0].meta.kdf.as_mut().unwrap();
        (kdf.m_kib, kdf.t, kdf.p) = (m, t, pp);
        let bytes = rebuild(&header, &p.header_mac, &p.body);
        assert_eq!(
            unlock_pw(&bytes, &f.pw_slot).err(),
            Some(Error::KdfOutOfBounds)
        );
    }
    let mut v = Vault::new(&mut TestRng(5)).unwrap();
    let r = v.add_password_slot(
        &mut TestRng(6),
        Factor::PasswordOnly,
        KdfCost {
            m_kib: 1024,
            t: 1,
            p: 1,
        },
        PW,
        None,
        "",
    );
    assert_eq!(r.err(), Some(Error::KdfOutOfBounds));
}

#[test]
fn swapped_item_data_is_rejected() {
    let mut rng = TestRng(0);
    let f = fixture(&mut rng);
    let mut v = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    let (a, b) = (v.items[0].clone(), v.items[1].clone());
    v.items[0].data_nonce = b.data_nonce;
    v.items[0].data_commit = b.data_commit;
    v.items[0].data_ciphertext = b.data_ciphertext.clone();
    assert_eq!(v.get_item(&a.item_id).err(), Some(Error::CorruptItem));
    // Replaying an older version of the same item is rejected too.
    v.items[0] = a.clone();
    v.put_item(&mut rng, &a.item_id, b"edited").unwrap();
    v.items[0].data_nonce = a.data_nonce;
    v.items[0].data_commit = a.data_commit;
    v.items[0].data_ciphertext = a.data_ciphertext;
    assert_eq!(v.get_item(&a.item_id).err(), Some(Error::CorruptItem));
}

#[test]
fn revoke_rotates_key_and_drops_unlisted_slots() {
    let mut rng = TestRng(0);
    let f = fixture(&mut rng);
    let mut v = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    let removed = v
        .revoke(
            &mut rng,
            &[
                (f.pw_slot, pw(PW)),
                (f.rec_slot, Unlock::Recovery { code: &f.code }),
            ],
        )
        .unwrap();
    assert_eq!(removed, vec![f.fido_slot]);
    assert_eq!(v.slot_label(&f.fido_slot), None);
    let newer = v.to_bytes(&mut rng).unwrap();

    let p = ParsedVault::parse(&newer).unwrap();
    assert_eq!(p.unlock(&f.fido_slot, &pw(PW)).err(), Some(Error::NotFound));
    let v2 = p
        .unlock(&f.rec_slot, &Unlock::Recovery { code: &f.code })
        .unwrap();
    assert_eq!(&**v2.get_item(&f.items[1]).unwrap(), b"item b");

    // The old file is still readable with the revoked factor: inherent, documented.
    let hw = HwKey::new([0xA5; 32]);
    ParsedVault::parse(&f.bytes)
        .unwrap()
        .unlock(
            &f.fido_slot,
            &Unlock::Password {
                password: PW,
                hw_key: Some(&hw),
            },
        )
        .unwrap();
}

#[test]
fn revoke_requires_valid_credentials_and_a_daily_slot() {
    let mut rng = TestRng(0);
    let f = fixture(&mut rng);
    let mut v = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    assert_eq!(
        v.revoke(&mut rng, &[(f.pw_slot, pw("nope"))]).err(),
        Some(Error::WrongFactor)
    );
    assert_eq!(
        v.revoke(
            &mut rng,
            &[(f.rec_slot, Unlock::Recovery { code: &f.code })]
        )
        .err(),
        Some(Error::LastSlot)
    );
    // Nothing changed after the failed attempts.
    assert_eq!(&**v.get_item(&f.items[0]).unwrap(), b"item a");
}

#[test]
fn cannot_remove_last_daily_slot() {
    let mut rng = TestRng(0);
    let f = fixture(&mut rng);
    let mut v = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    v.remove_slot(&f.fido_slot).unwrap();
    assert_eq!(v.remove_slot(&f.pw_slot).err(), Some(Error::LastSlot));
    v.remove_slot(&f.rec_slot).unwrap();
}

#[test]
fn generation_increments_on_every_write() {
    let mut rng = TestRng(0);
    let f = fixture(&mut rng);
    let mut v = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    let b2 = v.to_bytes(&mut rng).unwrap();
    assert_eq!(unlock_pw(&b2, &f.pw_slot).unwrap().generation(), 2);
}

#[test]
fn password_is_nfc_normalized() {
    let mut rng = TestRng(0);
    let mut v = Vault::new(&mut rng).unwrap();
    let composed = "caf\u{e9}";
    let decomposed = "cafe\u{301}";
    let slot = v
        .add_password_slot(&mut rng, Factor::PasswordOnly, COST, composed, None, "")
        .unwrap();
    let bytes = v.to_bytes(&mut rng).unwrap();
    ParsedVault::parse(&bytes)
        .unwrap()
        .unlock(&slot, &pw(decomposed))
        .unwrap();
}

#[test]
fn recovery_code_format_and_typos() {
    let f = fixture(&mut TestRng(0));
    assert_eq!(f.code.len(), 58 + 9);
    assert!(f.code.split('-').all(|g| g.len() <= 6));
    let p = ParsedVault::parse(&f.bytes).unwrap();
    let relaxed = f.code.replace('-', " ").to_lowercase();
    p.unlock(&f.rec_slot, &Unlock::Recovery { code: &relaxed })
        .unwrap();

    let mut typo: Vec<char> = f.code.chars().collect();
    typo[3] = if typo[3] == 'A' { 'B' } else { 'A' };
    let typo: String = typo.into_iter().collect();
    assert_eq!(
        p.unlock(&f.rec_slot, &Unlock::Recovery { code: &typo })
            .err(),
        Some(Error::BadRecoveryCode)
    );
    assert_eq!(
        p.unlock(
            &f.rec_slot,
            &Unlock::Recovery {
                code: &f.code[..20]
            }
        )
        .err(),
        Some(Error::BadRecoveryCode)
    );
    assert_eq!(
        p.unlock(&f.rec_slot, &pw(PW)).err(),
        Some(Error::FactorMismatch)
    );
}

#[test]
fn outer_layout_is_strict() {
    let f = fixture(&mut TestRng(0));
    let mut b = f.bytes.clone();
    b.push(0);
    assert_eq!(ParsedVault::parse(&b).err(), Some(Error::Malformed));
    assert_eq!(
        ParsedVault::parse(&f.bytes[..f.bytes.len() - 1]).err(),
        Some(Error::Malformed)
    );
    let mut b = f.bytes.clone();
    b[8] = 2;
    assert_eq!(ParsedVault::parse(&b).err(), Some(Error::Unsupported));
    let mut b = f.bytes.clone();
    b[0] ^= 1;
    assert_eq!(ParsedVault::parse(&b).err(), Some(Error::Malformed));
    assert_eq!(ParsedVault::parse(&[]).err(), Some(Error::Malformed));
}

#[test]
fn reserved_factor_slots_are_rejected() {
    let mut v = Vault::new(&mut TestRng(0)).unwrap();
    for f in [
        Factor::Recovery,
        Factor::PasswordDevice,
        Factor::RecipientHybrid,
    ] {
        let r = v.add_password_slot(&mut TestRng(1), f, COST, PW, None, "");
        assert_eq!(r.err(), Some(Error::FactorMismatch));
    }
}

#[test]
fn writing_requires_a_daily_slot() {
    let mut rng = TestRng(0);
    let mut v = Vault::new(&mut rng).unwrap();
    v.add_recovery_slot(&mut rng, "").unwrap();
    assert_eq!(v.to_bytes(&mut rng).err(), Some(Error::LastSlot));
}

mod props {
    use super::*;
    use proptest::prelude::*;
    use std::sync::OnceLock;

    fn sample() -> &'static Fixture {
        static F: OnceLock<Fixture> = OnceLock::new();
        F.get_or_init(|| fixture(&mut TestRng(0)))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = ParsedVault::parse(&bytes);
        }

        #[test]
        fn any_single_byte_flip_is_rejected(pos in any::<proptest::sample::Index>(), bit in 0u8..8) {
            let f = sample();
            let mut b = f.bytes.clone();
            let i = pos.index(b.len());
            b[i] ^= 1 << bit;
            // Must fail; a flip in a KDF parameter may also legitimately fail on bounds.
            prop_assert!(unlock_pw(&b, &f.pw_slot).is_err());
        }
    }
}
