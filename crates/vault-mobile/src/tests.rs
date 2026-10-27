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
