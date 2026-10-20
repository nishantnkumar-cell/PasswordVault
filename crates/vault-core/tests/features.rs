use vault_core::generator::{Charset, generate_passphrase, generate_password};
use vault_core::item::{ItemData, ItemKind, KeyData, UrlEntry};
use vault_core::origin::{MatchMode, Origin, may_fill};
use vault_core::totp::{TotpAlgorithm, TotpConfig};
use vault_core::*;

fn totp(secret: &[u8], alg: TotpAlgorithm) -> TotpConfig {
    TotpConfig {
        secret: secret.to_vec(),
        digits: 8,
        period: 30,
        algorithm: alg,
    }
}

#[test]
fn totp_rfc6238_vectors() {
    let s1 = b"12345678901234567890";
    let s256 = b"12345678901234567890123456789012";
    let s512 = b"1234567890123456789012345678901234567890123456789012345678901234";
    let cases: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ];
    for (t, a, b, c) in cases {
        assert_eq!(
            totp(s1, TotpAlgorithm::Sha1).code_at(t).unwrap(),
            a,
            "sha1 t={t}"
        );
        assert_eq!(
            totp(s256, TotpAlgorithm::Sha256).code_at(t).unwrap(),
            b,
            "sha256 t={t}"
        );
        assert_eq!(
            totp(s512, TotpAlgorithm::Sha512).code_at(t).unwrap(),
            c,
            "sha512 t={t}"
        );
    }
}

#[test]
fn totp_base32_and_defaults() {
    let t = TotpConfig::from_base32("jbsw y3dp ehpk 3pxp").unwrap();
    assert_eq!(t.secret, b"Hello!\xde\xad\xbe\xef");
    assert_eq!(
        (t.digits, t.period, t.algorithm),
        (6, 30, TotpAlgorithm::Sha1)
    );
    assert_eq!(t.code_at(0).unwrap().len(), 6);
    assert_eq!(t.remaining(61), 29);
    assert!(TotpConfig::from_base32("not base32!").is_err());
    assert!(TotpConfig::from_base32("").is_err());
}

#[test]
fn generated_passwords_cover_classes() {
    let mut rng = OsRandom;
    for _ in 0..200 {
        let p = generate_password(&mut rng, 16, Charset::default()).unwrap();
        assert_eq!(p.chars().count(), 16);
        assert!(p.chars().any(|c| c.is_ascii_lowercase()));
        assert!(p.chars().any(|c| c.is_ascii_uppercase()));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
        assert!(p.chars().any(|c| !c.is_ascii_alphanumeric()));
    }
    let cs = Charset {
        symbols: false,
        avoid_ambiguous: true,
        ..Charset::default()
    };
    for _ in 0..200 {
        let p = generate_password(&mut rng, 32, cs).unwrap();
        assert!(
            p.chars()
                .all(|c| c.is_ascii_alphanumeric() && !"0Oo1lI".contains(c))
        );
    }
    let none = Charset {
        lower: false,
        upper: false,
        digits: false,
        symbols: false,
        avoid_ambiguous: false,
    };
    assert!(generate_password(&mut rng, 16, none).is_err());
    assert!(generate_password(&mut rng, 2, Charset::default()).is_err());
}

#[test]
fn passphrase_uses_wordlist() {
    let words = ["alpha", "bravo", "charlie", "delta"];
    let p = generate_passphrase(&mut OsRandom, &words, 5, "-").unwrap();
    assert_eq!(p.split('-').count(), 5);
    assert!(p.split('-').all(|w| words.contains(&w)));
}

fn entry(url: &str, mode: MatchMode) -> UrlEntry {
    UrlEntry {
        url: url.into(),
        mode,
        allow_http: false,
    }
}

#[test]
fn origin_mode_is_exact() {
    let e = entry("https://accounts.example.com/login?x=1", MatchMode::Origin);
    assert!(may_fill(&e, "https://accounts.example.com"));
    assert!(may_fill(&e, "https://ACCOUNTS.example.com:443/other"));
    assert!(!may_fill(&e, "https://example.com"));
    assert!(!may_fill(&e, "https://evil.accounts.example.com"));
    assert!(!may_fill(&e, "https://accounts.example.com:8443"));
    assert!(!may_fill(&e, "http://accounts.example.com"));
    assert!(!may_fill(&e, "https://accounts.example.com.evil.net"));
    assert!(!may_fill(&e, "javascript:alert(1)"));
    assert!(!may_fill(&e, "not a url"));
}

#[test]
fn registrable_domain_mode_is_opt_in_and_https_only() {
    let e = entry("https://example.co.uk", MatchMode::RegistrableDomain);
    assert!(may_fill(&e, "https://login.example.co.uk"));
    assert!(!may_fill(&e, "https://example.com"));
    assert!(!may_fill(&e, "https://other.co.uk"));
    assert!(!may_fill(&e, "http://login.example.co.uk"));
    // Different users' sites on a public suffix are different registrable domains.
    let gh = entry("https://alice.github.io", MatchMode::RegistrableDomain);
    assert!(!may_fill(&gh, "https://mallory.github.io"));
    // IP addresses never widen.
    let ip = entry("https://192.168.1.10", MatchMode::RegistrableDomain);
    assert!(may_fill(&ip, "https://192.168.1.10"));
    assert!(!may_fill(&ip, "https://192.168.1.11"));
}

#[test]
fn http_needs_explicit_override() {
    let mut e = entry("http://router.local", MatchMode::Origin);
    assert!(!may_fill(&e, "http://router.local"));
    e.allow_http = true;
    assert!(may_fill(&e, "http://router.local"));
    let mut s = entry("https://bank.example", MatchMode::Origin);
    s.allow_http = true;
    assert!(
        !may_fill(&s, "http://bank.example"),
        "override only applies to http entries"
    );
}

#[test]
fn idn_hosts_are_normalized_and_flagged() {
    let o = Origin::parse("https://BÜCHER.example/").unwrap();
    assert_eq!(o.host, "xn--bcher-kva.example");
    assert!(o.has_punycode());
    // Cyrillic "а" lookalike does not match the Latin domain.
    let e = entry("https://apple.com", MatchMode::Origin);
    assert!(!may_fill(&e, "https://\u{0430}pple.com"));
    assert!(!Origin::parse("https://apple.com").unwrap().has_punycode());
}

#[test]
fn items_round_trip_through_a_vault() {
    let mut rng = OsRandom;
    let mut v = Vault::new(&mut rng).unwrap();
    let slot = v
        .add_password_slot(
            &mut rng,
            Factor::PasswordOnly,
            KdfCost::MINIMUM,
            "pw",
            None,
            "",
        )
        .unwrap();
    let mut item = ItemData::new(ItemKind::Login, "Example");
    item.username = "test-user".into();
    // Built at runtime: a dummy, not a credential.
    item.password = "x".repeat(16);
    item.urls = vec![entry("https://example.com", MatchMode::Origin)];
    item.totp = Some(TotpConfig::from_base32("JBSWY3DPEHPK3PXP").unwrap());
    item.notes = "note".into();
    item.created = 1;
    item.modified = 2;
    let id = v.new_item_id(&mut rng).unwrap();
    v.put_item(&mut rng, &id, &item.to_bytes()).unwrap();
    let bytes = v.to_bytes(&mut rng).unwrap();
    let v2 = ParsedVault::parse(&bytes)
        .unwrap()
        .unlock(
            &slot,
            &Unlock::Password {
                password: "pw",
                hw_key: None,
            },
        )
        .unwrap();
    let back = ItemData::from_bytes(&v2.get_item(&id).unwrap()).unwrap();
    assert!(back == item);
    assert!(ItemData::from_bytes(&[9, 9]).is_err());
}

#[test]
fn items_are_written_as_schema_3() {
    // Reading schemas 1 and 2 is covered by the unit tests in `item.rs`.
    let mut item = ItemData::default();
    item.title = "Now".into();
    let v3 = item.to_bytes();
    assert_eq!(v3[0], 3);
    assert!(ItemData::from_bytes(&v3).unwrap() == item);
    // Older tags on schema 3 bytes are rejected, and so is an unknown tag.
    for tag in [1, 2, 4] {
        let mut wrong = v3.to_vec();
        wrong[0] = tag;
        assert!(ItemData::from_bytes(&wrong).is_err(), "tag {tag}");
    }
}

#[test]
fn key_items_round_trip() {
    let mut item = ItemData::default();
    item.title = "laptop".into();
    item.key = Some(KeyData::Ssh {
        openssh: "-----BEGIN OPENSSH PRIVATE KEY-----\n...".into(),
        confirm: true,
    });
    let back = ItemData::from_bytes(&item.to_bytes()).unwrap();
    assert!(back == item);
    let mut k = back.key.clone().unwrap();
    assert!(k.confirm());
    k.set_confirm(false);
    assert!(!k.confirm());
}
