//! OpenPGP keys held in the vault (rPGP): generate or import, and sign,
//! decrypt, encrypt and verify inside the daemon, so the secret key never
//! leaves it.
//!
//! Two kinds of generated key:
//! - classic: v4, Ed25519 primary (certify, sign) with a Curve25519 ECDH
//!   encryption subkey, readable by GnuPG, Thunderbird and every current
//!   implementation;
//! - post-quantum: v6 (RFC 9580), ML-DSA-65+Ed25519 primary with an
//!   ML-KEM-768+X25519 encryption subkey (RFC 9980). Only implementations
//!   with RFC 9980 support can use it.
//!
//! RSA and DSA secret keys are refused: the `rsa` crate has no
//! constant-time fix for the Marvin attack. Encrypting to RSA certificates
//! and verifying RSA signatures (public operations) are allowed.

use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, EncryptionCaps,
    FullSignaturePacket, KeyType, Message, MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey,
    SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::PacketTrait;
use pgp::ser::Serialize;
use pgp::types::CompressionAlgorithm;
use pgp::types::{KeyDetails, KeyVersion, Password, SigningKey};
use rand::rngs::OsRng;
use vault_core::item::KeyData;
use zeroize::Zeroizing;

type R<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Parse a stored or supplied secret key (armored or binary).
fn secret(tsk: &[u8]) -> R<SignedSecretKey> {
    let (k, _) = SignedSecretKey::from_reader_single(tsk)
        .map_err(|e| format!("not an OpenPGP secret key: {e}"))?;
    Ok(k)
}

/// Parse a certificate (armored or binary). A secret key also works: its
/// public half is used.
pub fn certificate(bytes: &[u8]) -> R<SignedPublicKey> {
    if let Ok((k, _)) = SignedPublicKey::from_reader_single(bytes) {
        k.verify_bindings()
            .map_err(|e| format!("certificate is not valid: {e}"))?;
        return Ok(k);
    }
    Ok(secret(bytes)?.to_public_key())
}

fn rsa_or_dsa(a: PublicKeyAlgorithm) -> bool {
    matches!(
        a,
        PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::RSASign
            | PublicKeyAlgorithm::DSA
            | PublicKeyAlgorithm::ElgamalEncrypt
            | PublicKeyAlgorithm::Elgamal
    )
}

fn store(k: &SignedSecretKey, confirm: bool) -> R<KeyData> {
    if rsa_or_dsa(k.primary_key.algorithm())
        || k.secret_subkeys
            .iter()
            .any(|s| rsa_or_dsa(s.key.algorithm()))
    {
        return Err(
            "RSA, DSA and ElGamal secret keys are not supported; generate a new key with `vault pgp new`"
                .into(),
        );
    }
    let tsk = k.to_bytes().map_err(err)?;
    Ok(KeyData::OpenPgp { tsk, confirm })
}

/// A new key for `user_id` ("Name <mail@example.com>").
pub fn generate(user_id: &str, post_quantum: bool, confirm: bool) -> R<KeyData> {
    if user_id.trim().is_empty() {
        return Err("give a user ID, such as \"Name <mail@example.com>\"".into());
    }
    let (version, primary, enc) = if post_quantum {
        (
            KeyVersion::V6,
            KeyType::MlDsa65Ed25519,
            KeyType::MlKem768X25519,
        )
    } else {
        (
            KeyVersion::V4,
            KeyType::Ed25519Legacy,
            KeyType::ECDH(ECCCurve::Curve25519Legacy),
        )
    };
    let mut sub = SubkeyParamsBuilder::default();
    sub.version(version)
        .key_type(enc)
        .can_sign(false)
        .can_encrypt(EncryptionCaps::All)
        .can_authenticate(false);
    let mut params = SecretKeyParamsBuilder::default();
    params
        .version(version)
        .key_type(primary)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id(user_id.trim().into())
        // Without preferences, GnuPG falls back to SHA-1 when it signs mail
        // that it also encrypts to this key, and Thunderbird rejects SHA-1
        // signatures.
        .preferred_hash_algorithms(
            vec![
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha256,
            ]
            .into(),
        )
        .preferred_symmetric_algorithms(
            vec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ]
            .into(),
        )
        .preferred_compression_algorithms(
            vec![CompressionAlgorithm::ZLIB, CompressionAlgorithm::ZIP].into(),
        )
        .subkeys(vec![sub.build().map_err(err)?]);
    if post_quantum {
        params.feature_seipd_v2(true).preferred_aead_algorithms(
            vec![(SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb)].into(),
        );
    }
    let k = params.build().map_err(err)?.generate(OsRng).map_err(err)?;
    store(&k, confirm)
}

/// Read a secret key, removing its passphrase (the vault protects it).
pub fn import(bytes: &[u8], passphrase: Option<&str>, confirm: bool) -> R<KeyData> {
    let mut k = secret(bytes)?;
    k.verify_bindings()
        .map_err(|e| format!("the key's self-signatures are not valid: {e}"))?;
    let pw = Password::from(passphrase.unwrap_or(""));
    let wrong = |_| -> String {
        if passphrase.is_some() {
            "wrong passphrase for this key".into()
        } else {
            "this key is encrypted; give its passphrase".into()
        }
    };
    k.primary_key.remove_password(&pw).map_err(wrong)?;
    for s in &mut k.secret_subkeys {
        s.key.remove_password(&pw).map_err(wrong)?;
    }
    store(&k, confirm)
}

/// The certificate, ASCII-armored, to give to correspondents.
pub fn public_armored(tsk: &[u8]) -> R<String> {
    secret(tsk)?
        .to_public_key()
        .to_armored_string(ArmorOptions::default())
        .map_err(err)
}

/// The secret key, ASCII-armored and without a passphrase, for export.
pub fn secret_armored(tsk: &[u8]) -> R<Zeroizing<String>> {
    Ok(Zeroizing::new(
        secret(tsk)?
            .to_armored_string(ArmorOptions::default())
            .map_err(err)?,
    ))
}

/// `OpenPGP v4 EdDSALegacy 0123...ABCD Name <mail>` for listings.
pub fn describe(tsk: &[u8]) -> R<String> {
    let k = secret(tsk)?;
    let uid = k
        .details
        .users
        .first()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .unwrap_or_default();
    Ok(format!(
        "OpenPGP {:?} {:?} {} {uid}",
        k.primary_key.version(),
        k.primary_key.algorithm(),
        k.fingerprint()
    ))
}

/// The signing key: a subkey bound for signing, else the primary.
fn signer(k: &SignedSecretKey) -> &dyn SigningKey {
    k.secret_subkeys
        .iter()
        .find(|s| s.signatures.iter().any(|sig| sig.key_flags().sign()))
        .map(|s| &s.key as &dyn SigningKey)
        .unwrap_or(&k.primary_key)
}

/// A detached signature over `data`. `text`: a text signature, which
/// verifies whatever the line endings (LF or CRLF).
pub fn sign(tsk: &[u8], data: &[u8], armor: bool, text: bool) -> R<Vec<u8>> {
    let k = secret(tsk)?;
    let make = if text {
        DetachedSignature::sign_text_data
    } else {
        DetachedSignature::sign_binary_data
    };
    let sig = make(
        OsRng,
        &Box::new(signer(&k)),
        &Password::empty(),
        HashAlgorithm::Sha512,
        data,
    )
    .map_err(err)?;
    if armor {
        sig.to_armored_bytes(ArmorOptions::default()).map_err(err)
    } else {
        sig.to_bytes().map_err(err)
    }
}

/// A signed message that carries `data` (gpg's `--sign`), or with
/// `cleartext` a clear-signed text (`--clearsign`), which is always armored.
/// `text`: a text signature, as for [`sign`].
pub fn sign_message(
    tsk: &[u8],
    data: &[u8],
    cleartext: bool,
    armor: bool,
    text: bool,
) -> R<Vec<u8>> {
    let k = secret(tsk)?;
    if cleartext {
        let text = std::str::from_utf8(data).map_err(|_| "clear-signed text must be UTF-8")?;
        let text = trim_line_ends(text);
        let msg =
            CleartextSignedMessage::sign(OsRng, &text, &Box::new(signer(&k)), &Password::empty())
                .map_err(err)?;
        return msg.to_armored_bytes(ArmorOptions::default()).map_err(err);
    }
    let mut b = MessageBuilder::from_bytes("", data.to_vec());
    if text {
        b.sign_text();
    }
    b.sign(signer(&k), Password::empty(), HashAlgorithm::Sha512);
    if armor {
        b.to_armored_string(OsRng, ArmorOptions::default())
            .map(String::into_bytes)
            .map_err(err)
    } else {
        b.to_vec(OsRng).map_err(err)
    }
}

/// `text` without spaces and tabs at the ends of its lines. A clear
/// signature covers the text without them (RFC 9580, 7.2) and gpg removes
/// them from what it prints too; rPGP's signer leaves them in, so a mail
/// signature line "-- " would not verify anywhere else.
fn trim_line_ends(text: &str) -> String {
    text.split_inclusive('\n')
        .map(|line| {
            let body = line.trim_end_matches(['\r', '\n']);
            let end = &line[body.len()..];
            format!("{}{end}", body.trim_end_matches([' ', '\t']))
        })
        .collect()
}

/// Which of `certs` made `signature` over `data`: its fingerprint and
/// first user ID.
pub fn verify(certs: &[SignedPublicKey], data: &[u8], signature: &[u8]) -> R<String> {
    let (sig, _) = DetachedSignature::from_reader_single(signature)
        .map_err(|e| format!("not an OpenPGP signature: {e}"))?;
    for c in certs {
        if sig.verify(c, data).is_ok()
            || c.public_subkeys.iter().any(|s| sig.verify(s, data).is_ok())
        {
            let uid = c
                .details
                .users
                .first()
                .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
                .unwrap_or_default();
            return Ok(format!("{} {uid}", c.fingerprint()));
        }
    }
    Err("the signature does not verify with any of the given keys".into())
}

/// Encrypt `data` to every encryption-capable subkey of `certs`, optionally
/// signing with `sign_with`. SEIPDv2 (AEAD) when every recipient is a v6
/// key, else SEIPDv1 so v4 implementations can read it.
pub fn encrypt(
    certs: &[SignedPublicKey],
    data: &[u8],
    armor: bool,
    sign_with: Option<&[u8]>,
) -> R<Vec<u8>> {
    if certs.is_empty() {
        return Err("give at least one recipient".into());
    }
    let signing = sign_with.map(secret).transpose()?;
    let keys: Vec<_> = certs
        .iter()
        .map(|c| {
            let subs: Vec<_> = c
                .public_subkeys
                .iter()
                .filter(|s| {
                    s.key.algorithm().can_encrypt()
                        && s.signatures.iter().any(|sig| {
                            let f = sig.key_flags();
                            f.encrypt_comms() || f.encrypt_storage()
                        })
                })
                .collect();
            if subs.is_empty() {
                Err(format!("{} has no encryption subkey", c.fingerprint()))
            } else {
                Ok(subs)
            }
        })
        .collect::<R<_>>()?;
    let all_v6 = certs
        .iter()
        .all(|c| c.primary_key.version() == KeyVersion::V6);
    let builder = MessageBuilder::from_bytes("", data.to_vec());
    macro_rules! finish {
        ($b:expr) => {{
            let mut b = $b;
            for subs in &keys {
                for s in subs {
                    b.encrypt_to_key(OsRng, s).map_err(err)?;
                }
            }
            if let Some(k) = &signing {
                b.sign(signer(k), Password::empty(), HashAlgorithm::Sha512);
            }
            if armor {
                b.to_armored_string(OsRng, ArmorOptions::default())
                    .map(String::into_bytes)
                    .map_err(err)
            } else {
                b.to_vec(OsRng).map_err(err)
            }
        }};
    }
    if all_v6 {
        finish!(builder.seipd_v2(
            OsRng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default()
        ))
    } else {
        finish!(builder.seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256))
    }
}

/// Decrypt `message` with `tsk`, if it is one of the recipients.
pub fn decrypt(tsk: &[u8], message: &[u8]) -> R<Zeroizing<Vec<u8>>> {
    let k = secret(tsk)?;
    let msg = Message::from_reader(message)
        .map(|(m, _)| m)
        .or_else(|_| Message::from_bytes(message))
        .map_err(|e| format!("not an OpenPGP message: {e}"))?;
    let mut m = msg.decrypt(&Password::empty(), &k).map_err(err)?;
    if m.is_compressed() {
        m = m.decompress().map_err(err)?;
    }
    Ok(Zeroizing::new(m.as_data_vec().map_err(err)?))
}

/// Decrypt `message` with `tsk` but keep what was inside the encryption:
/// the OpenPGP message (uncompressed) with its signatures, as gpg's
/// `--decrypt --unwrap` prints it. Thunderbird decrypts mail for external
/// keys this way and checks the signatures itself.
pub fn unwrap(tsk: &[u8], message: &[u8]) -> R<Zeroizing<Vec<u8>>> {
    let k = secret(tsk)?;
    let msg = Message::from_reader(message)
        .map(|(m, _)| m)
        .or_else(|_| Message::from_bytes(message))
        .map_err(|e| format!("not an OpenPGP message: {e}"))?;
    let mut m = msg
        .decrypt(&Password::empty(), &k)
        .map_err(err)?
        .decompress()
        .map_err(err)?;
    let header = m
        .literal_data_header()
        .cloned()
        .ok_or("the message holds no literal data")?;
    // Reading to the end also checks the integrity tag and completes the
    // signatures of a one-pass signed message.
    let data = Zeroizing::new(m.as_data_vec().map_err(err)?);

    // Signature layers, outermost first.
    let mut layers: Vec<&[FullSignaturePacket]> = Vec::new();
    let mut cur = &m;
    while let Message::Signed { reader, .. } = cur {
        layers.push(reader.signatures().unwrap_or_default());
        cur = reader.get_ref();
    }
    let mut out = Zeroizing::new(Vec::with_capacity(data.len() + 1024));
    let w = &mut *out;
    for layer in &layers {
        for p in layer.iter() {
            if let FullSignaturePacket::Signature { signature } = p {
                signature.to_writer_with_header(w).map_err(err)?;
            }
        }
        for p in layer.iter() {
            if let FullSignaturePacket::Ops { ops, .. } = p {
                ops.to_writer_with_header(w).map_err(err)?;
            }
        }
    }
    write_literal(w, &header, &data);
    for layer in layers.iter().rev() {
        for p in layer.iter().rev() {
            if let FullSignaturePacket::Ops { signature, .. } = p {
                signature.to_writer_with_header(w).map_err(err)?;
            }
        }
    }
    Ok(out)
}

/// A literal data packet (new format) with `header`'s mode, name and date.
fn write_literal(out: &mut Vec<u8>, header: &pgp::packet::LiteralDataHeader, data: &[u8]) {
    let name = header.file_name();
    let name = &name[..name.len().min(255)];
    let len = 1 + 1 + name.len() + 4 + data.len();
    out.push(0xC0 | 11);
    if len < 192 {
        out.push(len as u8);
    } else if len < 8384 {
        let l = len - 192;
        out.push((l >> 8) as u8 + 192);
        out.push(l as u8);
    } else {
        out.push(0xFF);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.push(u8::from(header.mode()));
    out.push(name.len() as u8);
    out.extend_from_slice(name);
    out.extend_from_slice(&header.created().as_secs().to_be_bytes());
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tsk(k: KeyData) -> Vec<u8> {
        match k {
            KeyData::OpenPgp { tsk, .. } => tsk,
            _ => panic!(),
        }
    }

    fn round_trip(post_quantum: bool) {
        let alice = tsk(generate("Alice <alice@example.com>", post_quantum, true).unwrap());
        let bob = tsk(generate("Bob <bob@example.com>", post_quantum, true).unwrap());
        let cert_a = certificate(public_armored(&alice).unwrap().as_bytes()).unwrap();
        let cert_b = certificate(public_armored(&bob).unwrap().as_bytes()).unwrap();
        assert!(
            describe(&alice)
                .unwrap()
                .ends_with("Alice <alice@example.com>")
        );

        for armor in [true, false] {
            let ct = encrypt(
                std::slice::from_ref(&cert_b),
                b"hello bob",
                armor,
                Some(&alice),
            )
            .unwrap();
            assert_eq!(&**decrypt(&bob, &ct).unwrap(), b"hello bob");
            assert!(decrypt(&alice, &ct).is_err());

            let sig = sign(&alice, b"release", armor, false).unwrap();
            assert!(
                verify(&[cert_b.clone(), cert_a.clone()], b"release", &sig)
                    .unwrap()
                    .ends_with("Alice <alice@example.com>")
            );
            assert!(verify(std::slice::from_ref(&cert_a), b"tampered", &sig).is_err());
            assert!(verify(std::slice::from_ref(&cert_b), b"release", &sig).is_err());

            // Text signatures ignore line endings; binary ones do not.
            let text = sign(&alice, b"a\nb\n", armor, true).unwrap();
            assert!(verify(std::slice::from_ref(&cert_a), b"a\r\nb\r\n", &text).is_ok());
            let binary = sign(&alice, b"a\nb\n", armor, false).unwrap();
            assert!(verify(std::slice::from_ref(&cert_a), b"a\r\nb\r\n", &binary).is_err());
        }
    }

    #[test]
    fn classic_keys_round_trip() {
        round_trip(false);
    }

    #[test]
    fn post_quantum_keys_round_trip() {
        round_trip(true);
    }

    /// The literal data of a (decrypted) message, and whether its
    /// signature verifies with `cert`.
    fn read_signed(bytes: &[u8], cert: &SignedPublicKey) -> (Vec<u8>, bool) {
        let m = Message::from_reader(bytes)
            .map(|(m, _)| m)
            .or_else(|_| Message::from_bytes(bytes))
            .unwrap();
        let mut m = m.decompress().unwrap();
        let data = m.as_data_vec().unwrap();
        let ok = m.is_signed()
            && cert
                .public_subkeys
                .iter()
                .map(|s| &s.key as &dyn pgp::types::VerifyingKey)
                .chain([&cert.primary_key as &dyn pgp::types::VerifyingKey])
                .any(|k| m.verify(k).is_ok());
        (data, ok)
    }

    #[test]
    fn unwrap_keeps_the_signature() {
        for post_quantum in [false, true] {
            let alice = tsk(generate("Alice <alice@example.com>", post_quantum, false).unwrap());
            let bob = tsk(generate("Bob <bob@example.com>", post_quantum, false).unwrap());
            let cert_a = certificate(&alice).unwrap();
            let cert_b = certificate(&bob).unwrap();
            let body = b"line one\r\nline two\r\n".repeat(500);

            let ct = encrypt(std::slice::from_ref(&cert_b), &body, true, Some(&alice)).unwrap();
            let inner = unwrap(&bob, &ct).unwrap();
            assert_eq!(read_signed(&inner, &cert_a), (body.clone(), true));
            // Signed by Alice, so Bob's key does not verify it.
            assert!(!read_signed(&inner, &cert_b).1);
            assert!(unwrap(&alice, &ct).is_err());

            let ct = encrypt(std::slice::from_ref(&cert_b), b"plain", false, None).unwrap();
            let inner = unwrap(&bob, &ct).unwrap();
            assert_eq!(read_signed(&inner, &cert_a), (b"plain".to_vec(), false));
        }
    }

    #[test]
    fn signed_and_clear_signed_messages() {
        let alice = tsk(generate("Alice <alice@example.com>", false, false).unwrap());
        let cert = certificate(&alice).unwrap();
        for (armor, text) in [(false, false), (true, false), (false, true)] {
            let m = sign_message(&alice, b"to sign\n", false, armor, text).unwrap();
            assert_eq!(armor, m.starts_with(b"-----BEGIN PGP MESSAGE-----"));
            assert_eq!(read_signed(&m, &cert), (b"to sign\n".to_vec(), true));
        }
        let m = sign_message(
            &alice,
            b"Hello,\n- dash\n-- \nAlex \t\r\n",
            true,
            false,
            false,
        )
        .unwrap();
        let (msg, _) = CleartextSignedMessage::from_armor(&m[..]).unwrap();
        assert!(msg.verify(&cert.primary_key).is_ok());
        assert_eq!(msg.signed_text(), "Hello,\r\n- dash\r\n--\r\nAlex\r\n");
        assert!(sign_message(&alice, &[0xff, 0xfe], true, true, false).is_err());
    }

    #[test]
    fn import_removes_the_passphrase() {
        let k = secret(&tsk(generate("C <c@example.com>", false, false).unwrap())).unwrap();
        let mut locked = k.clone();
        let pw = Password::from("x".repeat(12).as_str());
        locked.primary_key.set_password(OsRng, &pw).unwrap();
        for s in &mut locked.secret_subkeys {
            s.key.set_password(OsRng, &pw).unwrap();
        }
        let armored = locked.to_armored_string(ArmorOptions::default()).unwrap();
        assert!(import(armored.as_bytes(), None, true).is_err());
        assert!(import(armored.as_bytes(), Some("wrong"), true).is_err());
        let back = tsk(import(armored.as_bytes(), Some(&"x".repeat(12)), true).unwrap());
        let cert = certificate(&back).unwrap();
        let ct = encrypt(&[cert], b"hi", false, None).unwrap();
        assert_eq!(&**decrypt(&back, &ct).unwrap(), b"hi");
    }
}
