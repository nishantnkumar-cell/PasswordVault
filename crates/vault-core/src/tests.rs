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
const GOLDEN_SHA256: &str = "e47b59546c6f2bf3c90292f627a2d7fea8b111b4ecb093b84ed7d8490833750b";

#[test]
fn body_v1_files_still_open() {
    // The golden file as written before body v2 (section 5.1), by the same
    // fixture: slot and item IDs match.
    let old = include_bytes!("testdata/body-v1.svault");
    let f = fixture(&mut TestRng(0));
    let mut v = unlock_pw(old, &f.pw_slot).unwrap();
    assert_eq!(v.generation(), 1);
    assert_eq!(&**v.get_item(&f.items[0]).unwrap(), b"item a");
    assert_eq!(v.slot_label(&f.fido_slot), Some("blue key"));

    let mut rng = TestRng(1);
    v.set_device(7);
    v.put_item(&mut rng, &f.items[0], b"item a2").unwrap();
    let newer = v.to_bytes(&mut rng).unwrap();
    let v = unlock_pw(&newer, &f.pw_slot).unwrap();
    assert_eq!(v.generation(), 2);
    assert_eq!(&**v.get_item(&f.items[0]).unwrap(), b"item a2");
    assert_eq!(
        v.clocks[&f.items[0]],
        v.clocks[&f.items[0]].clone().normalized()
    );
}

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

// ---- Merging (section 5.1) ----

/// Ranks by length; keeps a losing edit with " (conflict)" appended.
struct ByLength;

impl Resolve for ByLength {
    fn rank(&self, data: &[u8]) -> i64 {
        data.len() as i64
    }
    fn conflict_copy(&self, data: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new([data, b" (conflict)"].concat())
    }
}

/// Two devices holding the fixture vault.
fn two_devices(rng: &mut TestRng) -> (Fixture, Vault, Vault) {
    let f = fixture(rng);
    let mut a = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    let mut b = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    a.set_device(1);
    b.set_device(2);
    (f, a, b)
}

/// What a device would see after writing its copy and reopening the other's
/// file, both ways round.
fn sync(rng: &mut TestRng, a: &mut Vault, b: &mut Vault) -> (MergeReport, MergeReport) {
    let b_file = b.to_bytes(rng).unwrap();
    let theirs = ParsedVault::parse(&b_file).unwrap().open_with(a).unwrap();
    let ra = a.merge(rng, &theirs, &ByLength).unwrap();
    let a_file = a.to_bytes(rng).unwrap();
    let theirs = ParsedVault::parse(&a_file).unwrap().open_with(b).unwrap();
    let rb = b.merge(rng, &theirs, &ByLength).unwrap();
    (ra, rb)
}

/// Every item's data, sorted, to compare two copies.
fn contents(v: &Vault) -> Vec<(ItemId, Vec<u8>)> {
    let mut out: Vec<_> = v
        .item_ids()
        .map(|id| (*id, v.get_item(id).unwrap().to_vec()))
        .collect();
    out.sort();
    out
}

#[test]
fn merge_takes_both_sides_edits() {
    let mut rng = TestRng(0);
    let (f, mut a, mut b) = two_devices(&mut rng);
    let x = a.new_item_id(&mut rng).unwrap();
    a.put_item(&mut rng, &x, b"new on a").unwrap();
    b.put_item(&mut rng, &f.items[0], b"edited on b").unwrap();

    let (ra, rb) = sync(&mut rng, &mut a, &mut b);
    assert_eq!((ra.added, ra.updated, ra.conflicts), (0, 1, 0));
    assert!(ra.other_behind);
    assert_eq!((rb.added, rb.updated), (1, 0));
    assert!(!rb.other_behind);
    assert_eq!(contents(&a), contents(&b));
    assert_eq!(&**a.get_item(&f.items[0]).unwrap(), b"edited on b");
    assert_eq!(&**b.get_item(&x).unwrap(), b"new on a");

    // Idempotent: nothing left to do.
    let (ra, rb) = sync(&mut rng, &mut a, &mut b);
    assert!(!ra.changed() && !ra.other_behind);
    assert!(!rb.changed() && !rb.other_behind);
}

#[test]
fn concurrent_edits_keep_both_and_converge() {
    let mut rng = TestRng(0);
    let (f, mut a, mut b) = two_devices(&mut rng);
    a.put_item(&mut rng, &f.items[0], b"short").unwrap();
    b.put_item(&mut rng, &f.items[0], b"much longer").unwrap();

    let (ra, rb) = sync(&mut rng, &mut a, &mut b);
    assert_eq!((ra.updated, ra.conflicts), (1, 1));
    assert_eq!((rb.added, rb.conflicts), (1, 0));
    assert_eq!(contents(&a), contents(&b));
    let all = contents(&a);
    assert_eq!(all.len(), 3);
    assert_eq!(&**a.get_item(&f.items[0]).unwrap(), b"much longer");
    assert!(all.iter().any(|(_, d)| d == b"short (conflict)"));

    // Both devices resolving the same conflict on their own make the same copy.
    let mut rng = TestRng(0);
    let (f, mut a, mut b) = two_devices(&mut rng);
    a.put_item(&mut rng, &f.items[0], b"short").unwrap();
    b.put_item(&mut rng, &f.items[0], b"much longer").unwrap();
    let a_file = a.to_bytes(&mut rng).unwrap();
    let b_file = b.to_bytes(&mut rng).unwrap();
    let from_b = ParsedVault::parse(&b_file).unwrap().open_with(&a).unwrap();
    let from_a = ParsedVault::parse(&a_file).unwrap().open_with(&b).unwrap();
    a.merge(&mut rng, &from_b, &ByLength).unwrap();
    b.merge(&mut rng, &from_a, &ByLength).unwrap();
    assert_eq!(contents(&a), contents(&b));
    let (ra, _) = sync(&mut rng, &mut a, &mut b);
    assert!(!ra.changed());
}

#[test]
fn deletes_win_over_old_copies_and_lose_to_edits() {
    let mut rng = TestRng(0);
    let (f, mut a, mut b) = two_devices(&mut rng);
    let stale = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    a.remove_item(&f.items[0]).unwrap();
    a.remove_item(&f.items[1]).unwrap();
    b.put_item(&mut rng, &f.items[0], b"edited while deleted")
        .unwrap();

    let (ra, rb) = sync(&mut rng, &mut a, &mut b);
    assert_eq!(ra.added, 1);
    assert_eq!(rb.deleted, 1);
    assert_eq!(contents(&a), contents(&b));
    assert_eq!(a.item_ids().collect::<Vec<_>>(), vec![&f.items[0]]);

    // A copy from before the delete cannot bring item b back.
    let r = a.merge(&mut rng, &stale, &ByLength).unwrap();
    assert!(!r.changed());
    assert!(r.other_behind);
    assert_eq!(a.item_ids().count(), 1);

    // Deleting again after the edit was seen does delete it everywhere.
    a.remove_item(&f.items[0]).unwrap();
    let (_, rb) = sync(&mut rng, &mut a, &mut b);
    assert_eq!(rb.deleted, 1);
    assert_eq!(b.item_ids().count(), 0);
}

#[test]
fn merge_carries_slot_changes() {
    let mut rng = TestRng(0);
    let (f, mut a, mut b) = two_devices(&mut rng);
    let (new_slot, _) = a.add_recovery_slot(&mut rng, "second paper").unwrap();
    b.remove_slot(&f.fido_slot).unwrap();

    let (ra, rb) = sync(&mut rng, &mut a, &mut b);
    assert_eq!((ra.slots_added, ra.slots_removed), (0, 1));
    assert_eq!((rb.slots_added, rb.slots_removed), (1, 0));
    for v in [&a, &b] {
        let ids: Vec<_> = v.slots().map(|m| m.id).collect();
        assert!(ids.contains(&new_slot) && !ids.contains(&f.fido_slot));
        assert_eq!(v.slot_label(&new_slot), Some("second paper"));
    }
    // A stale copy cannot bring the removed slot back.
    let stale = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    a.merge(&mut rng, &stale, &ByLength).unwrap();
    assert!(!a.slots().any(|m| m.id == f.fido_slot));
}

#[test]
fn revoke_on_one_device_wins_the_key() {
    let mut rng = TestRng(0);
    let (f, mut a, mut b) = two_devices(&mut rng);
    a.revoke(
        &mut rng,
        &[
            (f.pw_slot, pw(PW)),
            (f.rec_slot, Unlock::Recovery { code: &f.code }),
        ],
    )
    .unwrap();
    let y = b.new_item_id(&mut rng).unwrap();
    b.put_item(&mut rng, &y, b"new on b").unwrap();

    let a_file = a.to_bytes(&mut rng).unwrap();
    let parsed = ParsedVault::parse(&a_file).unwrap();
    assert_eq!(parsed.open_with(&b).err(), Some(Error::DifferentKey));
    // b unlocks a's copy with the password instead.
    let mut theirs = parsed.unlock(&f.pw_slot, &pw(PW)).unwrap();
    theirs.set_device(2);
    let r = b.merge(&mut rng, &theirs, &ByLength).unwrap();
    assert!(r.rekeyed);
    assert_eq!(r.slots_dropped, vec![f.fido_slot]);
    assert!(r.other_behind);

    // b's file now opens only with the kept factors, under a's key.
    let b_file = b.to_bytes(&mut rng).unwrap();
    let p = ParsedVault::parse(&b_file).unwrap();
    assert_eq!(p.unlock(&f.fido_slot, &pw(PW)).err(), Some(Error::NotFound));
    let mut back = p.open_with(&a).unwrap();
    assert_eq!(&**back.get_item(&y).unwrap(), b"new on b");
    // a merges b's file without changing its key.
    let r = a.merge(&mut rng, &back, &ByLength).unwrap();
    assert!(!r.rekeyed);
    assert_eq!(r.added, 1);
    assert_eq!(contents(&a), contents(&back));
    // and the reverse direction is a no-op for b.
    let r = back.merge(&mut rng, &a, &ByLength).unwrap();
    assert!(!r.changed() && !r.other_behind);
}

#[test]
fn merge_refuses_another_vault() {
    let mut rng = TestRng(0);
    let f = fixture(&mut rng);
    let mut a = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    let mut other = Vault::new(&mut rng).unwrap();
    other
        .add_password_slot(&mut rng, Factor::PasswordOnly, COST, PW, None, "")
        .unwrap();
    assert_eq!(
        a.merge(&mut rng, &other, &ByLength).err(),
        Some(Error::DifferentVault)
    );
    let bytes = other.to_bytes(&mut rng).unwrap();
    assert_eq!(
        ParsedVault::parse(&bytes).unwrap().open_with(&a).err(),
        Some(Error::DifferentVault)
    );
}

mod merge_props {
    use super::*;
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum Op {
        Put(usize, usize, u8),
        Delete(usize, usize),
        Sync(usize, usize),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0..3usize, 0..4usize, any::<u8>()).prop_map(|(d, i, v)| Op::Put(d, i, v)),
            (0..3usize, 0..4usize).prop_map(|(d, i)| Op::Delete(d, i)),
            (0..3usize, 0..3usize).prop_map(|(a, b)| Op::Sync(a, b)),
        ]
    }

    /// Reopen a device's own file: a cheap stand-in for cloning a vault.
    fn copy(rng: &mut TestRng, v: &mut Vault) -> Vault {
        let bytes = v.to_bytes(rng).unwrap();
        ParsedVault::parse(&bytes).unwrap().open_with(v).unwrap()
    }

    fn pull(rng: &mut TestRng, devs: &mut [Vault], to: usize, from: usize) {
        if to == from {
            return;
        }
        let theirs = copy(rng, &mut devs[from]);
        devs[to].merge(rng, &theirs, &ByLength).unwrap();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// However edits, deletes and partial syncs interleave, devices that
        /// finally exchange copies hold the same items.
        #[test]
        fn devices_converge(ops in proptest::collection::vec(op(), 0..24)) {
            let mut rng = TestRng(0);
            let mut base = Vault::new(&mut rng).unwrap();
            base.add_password_slot(&mut rng, Factor::PasswordOnly, COST, PW, None, "").unwrap();
            let ids: Vec<ItemId> = (0..4).map(|_| base.new_item_id(&mut rng).unwrap()).collect();
            let mut devs: Vec<Vault> = (0..3)
                .map(|d| {
                    let mut v = copy(&mut rng, &mut base);
                    v.set_device(d as u64 + 1);
                    v
                })
                .collect();
            for op in ops {
                match op {
                    Op::Put(d, i, v) => devs[d].put_item(&mut rng, &ids[i], &vec![v; 1 + v as usize % 5]).unwrap(),
                    Op::Delete(d, i) => { let _ = devs[d].remove_item(&ids[i]); }
                    Op::Sync(a, b) => pull(&mut rng, &mut devs, a, b),
                }
            }
            for _ in 0..2 {
                for a in 0..3 {
                    for b in 0..3 {
                        pull(&mut rng, &mut devs, a, b);
                    }
                }
            }
            let first = contents(&devs[0]);
            for d in &devs[1..] {
                prop_assert_eq!(&contents(d), &first);
            }
            // Nothing left to exchange.
            let theirs = copy(&mut rng, &mut devs[1]);
            let r = devs[0].merge(&mut rng, &theirs, &ByLength).unwrap();
            prop_assert!(!r.changed() && !r.other_behind);
        }
    }
}

#[test]
fn parked_key_resumes_only_with_its_wrap_key_and_vault_key() {
    let mut rng = TestRng(0);
    let f = fixture(&mut rng);
    let mut v = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    let wrap = HwKey::new([0x5A; 32]);
    let parked = v.park(&wrap, &mut rng).unwrap();
    let p = ParsedVault::parse(&f.bytes).unwrap();
    let back = p.resume(&parked, &wrap).unwrap();
    assert_eq!(&**back.get_item(&f.items[0]).unwrap(), b"item a");
    assert_eq!(
        p.resume(&parked, &HwKey::new([0x5B; 32])).err(),
        Some(Error::WrongFactor)
    );

    // Another vault, and the same vault after its key was rotated, refuse it.
    let other = fixture(&mut TestRng(99));
    let q = ParsedVault::parse(&other.bytes).unwrap();
    assert_eq!(q.resume(&parked, &wrap).err(), Some(Error::DifferentVault));
    v.revoke(&mut rng, &[(f.pw_slot, pw(PW))]).unwrap();
    let rotated = v.to_bytes(&mut rng).unwrap();
    let r = ParsedVault::parse(&rotated).unwrap();
    assert_eq!(r.resume(&parked, &wrap).err(), Some(Error::DifferentKey));
}

#[test]
fn parked_key_round_trips_through_bytes() {
    let mut rng = TestRng(0);
    let f = fixture(&mut rng);
    let v = unlock_pw(&f.bytes, &f.pw_slot).unwrap();
    let wrap = HwKey::new([0x5A; 32]);
    let bytes = v.park(&wrap, &mut rng).unwrap().to_bytes();
    let parked = ParkedKey::from_bytes(&bytes).unwrap();
    assert_eq!(parked.vault_id(), v.vault_id());
    let p = ParsedVault::parse(&f.bytes).unwrap();
    let back = p.resume(&parked, &wrap).unwrap();
    assert_eq!(&**back.get_item(&f.items[0]).unwrap(), b"item a");

    // Truncated, padded or retagged bytes are refused before any crypto.
    assert!(ParkedKey::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    assert!(ParkedKey::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_err());
    let mut bad = bytes.clone();
    bad[0] ^= 1;
    assert!(ParkedKey::from_bytes(&bad).is_err());
    // A flipped ciphertext bit fails to open.
    let mut flipped = bytes;
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    let parked = ParkedKey::from_bytes(&flipped).unwrap();
    assert_eq!(p.resume(&parked, &wrap).err(), Some(Error::WrongFactor));
}
