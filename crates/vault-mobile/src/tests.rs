use super::*;

const PW: &str = "correct horse battery";

fn new_vault() -> NewVault {
    create_with_cost(PW.into(), 1, KdfCost::MINIMUM).unwrap()
}

fn login(title: &str, url: &str) -> ItemEdit {
    ItemEdit {
        kind: Kind::Login,
        title: title.into(),
        username: "alex@example.com".into(),
        password: ["pa", "ss", "word"].concat(),
        urls: vec![UrlRecord {
            url: url.into(),
            match_subdomains: false,
            allow_http: false,
        }],
        totp: TotpEdit::Set {
            input: "JBSWY3DPEHPK3PXP".into(),
        },
        card: None,
        identity: None,
        fields: vec![],
        notes: String::new(),
    }
}

#[test]
fn create_save_reopen_with_password_and_recovery() {
    let nv = new_vault();
    let s = &nv.session;
    let id = s.save_item(None, login("GitHub", "github.com")).unwrap();
    let bytes = s.to_bytes().unwrap();

    let locked = LockedVault::new(bytes).unwrap();
    assert!(locked.has_password_slot());
    assert_eq!(locked.vault_id(), s.vault_id());
    assert!(matches!(
        locked.unlock_password("wrong password".into(), 2),
        Err(MobileError::WrongCredential)
    ));
    let a = locked.unlock_password(PW.into(), 2).unwrap();
    let item = a.item(id.clone()).unwrap();
    assert_eq!(item.title, "GitHub");
    assert_eq!(item.urls[0].url, "https://github.com");
    assert!(item.has_totp);
    let b = locked.unlock_recovery(nv.recovery_code.clone(), 2).unwrap();
    assert_eq!(b.items().len(), 1);
    let slots = b.slots();
    assert!(
        slots
            .iter()
            .any(|s| s.factor == "password" && s.label == "password")
    );
    assert!(slots.iter().any(|s| s.factor == "recovery code"));
}

#[test]
fn biometric_park_and_resume() {
    let nv = new_vault();
    let wrap = vec![7u8; 32];
    let parked = nv.session.park(wrap.clone()).unwrap();
    let locked = LockedVault::new(nv.session.to_bytes().unwrap()).unwrap();
    assert!(locked.resume(parked.clone(), wrap, 1).is_ok());
    assert!(matches!(
        locked.resume(parked.clone(), vec![8u8; 32], 1),
        Err(MobileError::WrongCredential)
    ));
    assert!(locked.resume(parked, vec![7u8; 31], 1).is_err());
}

#[test]
fn edit_keeps_seed_and_created_time() {
    let s = new_vault().session;
    let id = s
        .save_item(None, login("GitHub", "https://github.com"))
        .unwrap();
    let before = s.item(id.clone()).unwrap();
    let mut e = login("GitHub (personal)", "https://github.com");
    e.totp = TotpEdit::Keep;
    s.save_item(Some(id.clone()), e).unwrap();
    let after = s.item(id.clone()).unwrap();
    assert_eq!(after.title, "GitHub (personal)");
    assert!(after.has_totp);
    assert_eq!(after.created, before.created);
    let code = s.totp(id.clone(), 59).unwrap().unwrap();
    assert_eq!(code.code.len(), 6);
    assert_eq!(code.remaining, 1);

    let mut e = login("GitHub", "https://github.com");
    e.totp = TotpEdit::Remove;
    s.save_item(Some(id.clone()), e).unwrap();
    assert!(s.totp(id.clone(), 0).unwrap().is_none());
    s.delete_item(id.clone()).unwrap();
    assert!(matches!(s.item(id), Err(MobileError::NotFound)));
}

#[test]
fn bad_input_is_refused() {
    let s = new_vault().session;
    let mut e = login("  ", "https://github.com");
    assert!(matches!(
        s.save_item(None, e.clone()),
        Err(MobileError::Invalid { .. })
    ));
    e.title = "x".into();
    e.totp = TotpEdit::Set {
        input: "not base32!".into(),
    };
    assert!(matches!(
        s.save_item(None, e),
        Err(MobileError::Invalid { .. })
    ));
    assert!(matches!(s.item("zz".into()), Err(MobileError::NotFound)));
    assert!(create_with_cost("short".into(), 1, KdfCost::MINIMUM).is_err());
}

#[test]
fn autofill_matches_origin_only() {
    let s = new_vault().session;
    s.save_item(None, login("GitHub", "https://github.com"))
        .unwrap();
    let mut wide = login("Example", "https://www.example.com");
    wide.urls[0].match_subdomains = true;
    s.save_item(None, wide).unwrap();
    assert_eq!(s.logins_for("github.com".into()).len(), 1);
    assert_eq!(s.logins_for("https://github.com/login".into()).len(), 1);
    assert!(s.logins_for("github.com.evil.example".into()).is_empty());
    assert!(s.logins_for("http://github.com".into()).is_empty());
    assert_eq!(
        s.logins_for("accounts.example.com".into())[0].title,
        "Example"
    );
}

#[test]
fn cards_and_identities_round_trip() {
    let s = new_vault().session;
    let mut e = login("Visa", "");
    e.kind = Kind::Card;
    e.card = Some(CardRecord {
        holder: "Alex Example".into(),
        number: "4242 4242 4242 4242".into(),
        exp_month: 8,
        exp_year: 2029,
        ..Default::default()
    });
    let id = s.save_item(None, e).unwrap();
    let d = s.item(id).unwrap();
    let c = d.card.unwrap();
    assert_eq!(c.number, "4242424242424242");
    assert_eq!(c.brand.as_deref(), Some("Visa"));
    assert!(c.number_valid);
    // Login parts are cleared for a card.
    assert!(d.username.is_empty() && !d.has_totp && d.urls.is_empty());
    let list = s.items();
    assert_eq!(list[0].kind, Kind::Card);
    assert!(list[0].subtitle.contains("4242"));
}

#[test]
fn sync_merge_between_two_phones() {
    let a = new_vault().session;
    let bytes = a.to_bytes().unwrap();
    let b = LockedVault::new(bytes)
        .unwrap()
        .unlock_password(PW.into(), 2)
        .unwrap();
    a.save_item(None, login("GitHub", "https://github.com"))
        .unwrap();
    b.save_item(None, login("GitLab", "https://gitlab.com"))
        .unwrap();
    let r = a.merge(b.to_bytes().unwrap(), None).unwrap();
    assert!(r.changed && r.other_behind);
    let r = b.merge(a.to_bytes().unwrap(), None).unwrap();
    assert!(r.changed && !r.other_behind);
    assert_eq!(a.items().len(), 2);
    assert_eq!(b.items().len(), 2);
    let other = new_vault().session;
    assert!(matches!(
        a.merge(other.to_bytes().unwrap(), None),
        Err(MobileError::DifferentVault)
    ));
}

#[test]
fn helpers() {
    let p = generate_password(GeneratorOptions {
        length: 24,
        lower: true,
        upper: true,
        digits: true,
        symbols: false,
        avoid_ambiguous: true,
    })
    .unwrap();
    assert_eq!(p.chars().count(), 24);
    assert!(
        generate_password(GeneratorOptions {
            length: 24,
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            avoid_ambiguous: false,
        })
        .is_err()
    );
    assert_eq!(
        host_of("GitHub.com/login".into()).as_deref(),
        Some("github.com")
    );
    assert!(host_of("ftp://x".into()).is_none());
    assert_eq!(
        preview_totp("JBSWY3DPEHPK3PXP".into(), 0).unwrap().period,
        30
    );
}

#[test]
fn add_code_to_a_new_or_existing_login() {
    let v = new_vault();
    let s = v.session;
    let link = "otpauth://totp/Example:alex%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    assert_eq!(
        code_label(link.into()),
        Some(CodeLabel {
            issuer: "Example".into(),
            account: "alex@example.com".into()
        })
    );
    assert!(code_label("JBSWY3DPEHPK3PXP".into()).is_none());

    // A new login takes its name from the link.
    let id = s
        .add_code(link.into(), String::new(), String::new(), None)
        .unwrap();
    let d = s.item(id.clone()).unwrap();
    assert_eq!(
        (d.title.as_str(), d.username.as_str()),
        ("Example", "alex@example.com")
    );
    assert!(d.has_totp && d.password.is_empty());
    // A bare key needs a name.
    assert!(
        s.add_code("JBSWY3DPEHPK3PXP".into(), " ".into(), String::new(), None)
            .is_err()
    );

    // An existing login keeps everything else.
    let mut edit = login("Mail", "https://mail.example.com");
    edit.totp = TotpEdit::Keep;
    let mail = s.save_item(None, edit).unwrap();
    assert!(!s.item(mail.clone()).unwrap().has_totp);
    let same = s
        .add_code(
            "JBSWY3DPEHPK3PXP".into(),
            String::new(),
            String::new(),
            Some(mail.clone()),
        )
        .unwrap();
    assert_eq!(same, mail);
    let d = s.item(mail).unwrap();
    assert!(d.has_totp);
    assert_eq!(d.password, ["pa", "ss", "word"].concat());
    assert!(
        s.add_code("not a key!".into(), "X".into(), String::new(), None)
            .is_err()
    );

    // A secure note can't keep a code, so it is refused, not dropped.
    let mut note = login("Router", "");
    note.kind = Kind::Note;
    note.totp = TotpEdit::Keep;
    let note = s.save_item(None, note).unwrap();
    assert!(
        s.add_code(
            "JBSWY3DPEHPK3PXP".into(),
            String::new(),
            String::new(),
            Some(note)
        )
        .is_err()
    );
}

#[test]
fn styled_passwords() {
    let words = generate_styled(PasswordStyle::Words {
        words: 4,
        separator: "-".into(),
        capitalize: false,
        number_and_symbol: false,
    })
    .unwrap();
    assert_eq!(words.split('-').count(), 4);
    let apple = generate_styled(PasswordStyle::Apple).unwrap();
    assert_eq!(apple.len(), 20);
    assert!(password_strength(PasswordStyle::Apple) > 70.0);
    assert_eq!(
        password_strength(PasswordStyle::Words {
            words: 1,
            separator: String::new(),
            capitalize: true,
            number_and_symbol: false
        }) as u32,
        12
    );
}

#[test]
fn change_password_keeps_items_and_recovery() {
    let nv = new_vault();
    let s = &nv.session;
    s.save_item(None, login("GitHub", "github.com")).unwrap();
    assert!(matches!(
        s.change_password("wrong password".into(), "a new master password".into()),
        Err(MobileError::WrongCredential)
    ));
    assert!(matches!(
        s.change_password(PW.into(), "short".into()),
        Err(MobileError::Invalid { .. })
    ));
    s.change_password(PW.into(), "a new master password".into())
        .unwrap();
    assert_eq!(
        s.slots().iter().filter(|x| x.factor == "password").count(),
        1
    );

    let locked = LockedVault::new(s.to_bytes().unwrap()).unwrap();
    assert!(matches!(
        locked.unlock_password(PW.into(), 2),
        Err(MobileError::WrongCredential)
    ));
    let a = locked
        .unlock_password("a new master password".into(), 2)
        .unwrap();
    assert_eq!(a.items().len(), 1);
    locked.unlock_recovery(nv.recovery_code.clone(), 2).unwrap();
}

#[test]
fn new_recovery_code_replaces_the_old_one() {
    let nv = new_vault();
    let s = &nv.session;
    let code = s.new_recovery_code().unwrap();
    assert_ne!(code, nv.recovery_code);
    assert_eq!(
        s.slots()
            .iter()
            .filter(|x| x.factor == "recovery code")
            .count(),
        1
    );
    let locked = LockedVault::new(s.to_bytes().unwrap()).unwrap();
    assert!(locked.unlock_recovery(nv.recovery_code.clone(), 2).is_err());
    locked.unlock_recovery(code, 2).unwrap();
}

#[test]
fn remove_slot_keeps_the_last_password() {
    let nv = new_vault();
    let s = &nv.session;
    let slots = s.slots();
    let pw = slots.iter().find(|x| x.factor == "password").unwrap();
    let rc = slots.iter().find(|x| x.factor == "recovery code").unwrap();
    assert!(matches!(
        s.remove_slot(pw.id.clone()),
        Err(MobileError::Invalid { .. })
    ));
    s.remove_slot(rc.id.clone()).unwrap();
    assert_eq!(s.slots().len(), 1);
    assert!(s.remove_slot(rc.id.clone()).is_err());
}

#[test]
fn revoke_others_rekeys_and_makes_a_new_code() {
    let nv = new_vault();
    let s = &nv.session;
    let id = s.save_item(None, login("GitHub", "github.com")).unwrap();
    // Another phone with the old key, holding a stale copy.
    let old = LockedVault::new(s.to_bytes().unwrap())
        .unwrap()
        .unlock_password(PW.into(), 2)
        .unwrap();
    assert!(matches!(
        s.revoke_others("wrong password".into()),
        Err(MobileError::WrongCredential)
    ));
    let code = s.revoke_others(PW.into()).unwrap();
    let factors: Vec<String> = s.slots().into_iter().map(|x| x.factor).collect();
    assert_eq!(factors, ["password", "recovery code"]);

    let bytes = s.to_bytes().unwrap();
    let locked = LockedVault::new(bytes.clone()).unwrap();
    assert!(locked.unlock_recovery(nv.recovery_code.clone(), 3).is_err());
    let b = locked.unlock_recovery(code, 3).unwrap();
    assert_eq!(b.item(id).unwrap().title, "GitHub");
    // The other device needs the password once to take the new key.
    assert!(matches!(
        old.merge(bytes.clone(), None),
        Err(MobileError::Rekeyed)
    ));
    assert!(old.merge(bytes, Some(PW.into())).unwrap().rekeyed);
}

#[test]
fn import_bitwarden_and_csv() {
    let nv = new_vault();
    let s = &nv.session;
    let json = r#"{"encrypted":false,"items":[
        {"type":1,"name":"Example","login":{"username":"alex@example.com","password":"pw",
         "uris":[{"uri":"https://example.com/login"}]}},
        {"type":2,"name":"Wifi","notes":"pass: abc"},
        {"type":5,"name":"SSH key"}]}"#;
    let r = s.import_export(format!("\u{feff}  {json}")).unwrap();
    assert_eq!(
        (r.imported, r.skipped, r.format.as_str()),
        (2, 1, "Bitwarden")
    );

    // Apple Passwords' export.
    let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
               Shop,https://shop.example.com/,alex@example.com,pw2,,otpauth://totp/Shop?secret=JBSWY3DPEHPK3PXP\n";
    let r = s.import_export(csv.into()).unwrap();
    assert_eq!((r.imported, r.format.as_str()), (1, "CSV"));
    let shop = s.items().into_iter().find(|i| i.title == "Shop").unwrap();
    assert!(shop.has_totp);
    assert_eq!(s.items().len(), 3);

    assert!(matches!(
        s.import_export("not,an,export\n1,2,3\n".into()),
        Err(MobileError::Invalid { .. })
    ));
    assert!(matches!(
        s.import_export(r#"{"encrypted":true,"items":[]}"#.into()),
        Err(MobileError::Invalid { .. })
    ));
}

#[test]
fn ssh_keys_generate_and_show_public_half() {
    let nv = new_vault();
    let s = &nv.session;
    assert!(
        s.generate_ssh_key("  ".into(), SshKeyKind::Ed25519, false)
            .is_err()
    );
    let id = s
        .generate_ssh_key("Laptop".into(), SshKeyKind::Ed25519, true)
        .unwrap();
    let k = s.key_public(id.clone()).unwrap().unwrap();
    assert_eq!(
        (k.kind.as_str(), k.algorithm.as_str()),
        ("SSH", "ssh-ed25519")
    );
    assert!(k.public_text.starts_with("ssh-ed25519 AAAA") && k.public_text.ends_with(" Laptop"));
    assert!(k.fingerprint.starts_with("SHA256:"));
    assert!(k.confirm);
    let summary = s.items().into_iter().find(|i| i.id == id).unwrap();
    assert!(summary.has_key);

    let id = s
        .generate_ssh_key("Old server".into(), SshKeyKind::EcdsaP256, false)
        .unwrap();
    let k = s.key_public(id).unwrap().unwrap();
    assert_eq!(k.algorithm, "ecdsa-sha2-nistp256");

    let plain = s.save_item(None, login("GitHub", "github.com")).unwrap();
    assert!(s.key_public(plain).unwrap().is_none());
}

#[test]
fn openpgp_public_half() {
    use pgp::composed::{KeyType, SecretKeyParamsBuilder};
    use pgp::ser::Serialize;
    use vault_core::item::{ItemData, KeyData};

    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("Alex Example <alex@example.com>".into());
    let k = params.build().unwrap().generate(rand::rngs::OsRng).unwrap();
    let mut item = ItemData::default();
    item.title = "Mail".into();
    item.key = Some(KeyData::OpenPgp {
        tsk: k.to_bytes().unwrap(),
        confirm: false,
    });

    let nv = new_vault();
    let s = &nv.session;
    let id = {
        let mut v = s.lock();
        let id = v.new_item_id(&mut OsRandom).unwrap();
        v.put_item(&mut OsRandom, &id, &item.to_bytes()).unwrap();
        hex(&id)
    };
    let p = s.key_public(id).unwrap().unwrap();
    assert_eq!(p.kind, "OpenPGP");
    assert!(
        p.public_text
            .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    );
    assert_eq!(p.fingerprint.len(), 40);
    assert!(!p.public_text.contains("PRIVATE"));
}
