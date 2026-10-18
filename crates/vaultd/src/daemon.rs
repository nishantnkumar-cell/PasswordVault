//! Request handling: authorization, unlock with rate limiting, the vault
//! operations, rollback refusal and idle lock.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use vault_core::generator::{Charset, generate_password};
use vault_core::item::ItemData;
use vault_core::origin::may_fill;
use vault_core::{
    Factor, HwKey, ItemId, KdfCost, KeyslotMeta, OsRandom, ParsedVault, PcrPolicy, SecureRandom,
    SlotId, Unlock, Vault,
};
use vault_ipc::{
    ClientScope, ClientToken, Envelope, ImportFormat, ItemSummary, Request, Response, Secret,
    SlotInfo, StatusInfo, UnlockMethod,
};
use zeroize::Zeroizing;

use crate::hw::{Hardware, prf_salt};
use crate::store::Store;

/// Relying party ID for FIDO2 credentials created by this daemon.
pub const RP_ID: &str = "vault.local";

/// Failed attempts allowed before backoff starts.
const FREE_ATTEMPTS: u32 = 3;
/// Longest wait between attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(300);

pub struct Daemon {
    store: Store,
    hw: Hardware,
    cost: KdfCost,
    idle: Duration,
    vault: Option<Vault>,
    last_activity: Instant,
    rollback: bool,
    failures: u32,
    next_attempt: Option<Instant>,
}

type R<T> = Result<T, String>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn e(err: vault_core::Error) -> String {
    err.to_string()
}

/// A credential for one slot, owned so it can be borrowed as [`Unlock`].
enum Cred {
    Password(Secret, Option<HwKey>),
    Recovery(Secret),
}

impl Cred {
    fn as_unlock(&self) -> Unlock<'_> {
        match self {
            Cred::Password(p, hw) => Unlock::Password {
                password: p,
                hw_key: hw.as_ref(),
            },
            Cred::Recovery(c) => Unlock::Recovery { code: c },
        }
    }
}

fn kind(f: &Factor) -> &'static str {
    match f {
        Factor::PasswordOnly => "password",
        Factor::PasswordFido2 { .. } => "fido2",
        Factor::PasswordTpm { .. } => "tpm",
        Factor::Recovery => "recovery",
        _ => "reserved",
    }
}

fn token(rng: &mut OsRandom) -> R<ClientToken> {
    let mut t = Zeroizing::new([0u8; 32]);
    rng.fill(&mut t[..]).map_err(e)?;
    Ok(t)
}

impl Daemon {
    pub fn new(store: Store, hw: Hardware, cost: KdfCost, idle: Duration) -> Daemon {
        Daemon {
            store,
            hw,
            cost,
            idle,
            vault: None,
            last_activity: Instant::now(),
            rollback: false,
            failures: 0,
            next_attempt: None,
        }
    }

    /// Lock if idle for longer than the timeout. Called periodically.
    pub fn tick(&mut self) {
        if self.vault.is_some() && self.last_activity.elapsed() >= self.idle {
            self.lock();
        }
    }

    /// Drop the vault and its keys.
    pub fn lock(&mut self) {
        self.vault = None;
    }

    pub fn handle(&mut self, env: Envelope) -> Response {
        match self.dispatch(env) {
            Ok(r) => r,
            Err(m) => Response::Error(m),
        }
    }

    fn dispatch(&mut self, env: Envelope) -> R<Response> {
        let scope = match &env.request {
            Request::Status | Request::Init { .. } | Request::Pair { .. } => None,
            _ => {
                let t = env
                    .token
                    .as_ref()
                    .ok_or("this client is not paired; run `vault pair`")?;
                Some(
                    self.store
                        .client_scope(t)
                        .ok_or("unknown client token; pair again")?,
                )
            }
        };
        if scope == Some(ClientScope::Autofill)
            && !matches!(
                env.request,
                Request::Unlock { .. }
                    | Request::Lock
                    | Request::FindForOrigin { .. }
                    | Request::GetForFill { .. }
                    | Request::TotpForFill { .. }
                    | Request::Generate { .. }
            )
        {
            return Err("not allowed for an autofill client".into());
        }
        if scope.is_some() {
            self.last_activity = Instant::now();
        }

        match env.request {
            Request::Status => Ok(Response::Status(self.status())),
            Request::Init {
                password,
                client_name,
            } => self.init(&password, &client_name),
            Request::Pair {
                client_name,
                scope,
                method,
            } => {
                self.vault = Some(self.prove(&method)?);
                let t = token(&mut OsRandom)?;
                self.store
                    .add_client(&client_name, scope, &t)
                    .map_err(|e| e.to_string())?;
                Ok(Response::Paired { token: t })
            }
            Request::Unlock { method } => {
                self.vault = Some(self.prove(&method)?);
                Ok(Response::Ok)
            }
            Request::Lock => {
                self.lock();
                Ok(Response::Ok)
            }
            Request::Generate { options } => {
                let cs = Charset {
                    symbols: options.symbols,
                    avoid_ambiguous: options.avoid_ambiguous,
                    ..Charset::default()
                };
                let pw =
                    generate_password(&mut OsRandom, usize::from(options.length.clamp(8, 256)), cs)
                        .map_err(e)?;
                Ok(Response::Generated(pw))
            }
            other => self.unlocked(other),
        }
    }

    fn status(&self) -> StatusInfo {
        StatusInfo {
            initialized: self.store.exists(),
            unlocked: self.vault.is_some(),
            generation: self.vault.as_ref().map(Vault::generation),
            rollback_detected: self.rollback,
            idle_lock_in: self.vault.as_ref().map(|_| {
                self.idle
                    .saturating_sub(self.last_activity.elapsed())
                    .as_secs()
            }),
        }
    }

    fn init(&mut self, password: &str, client_name: &str) -> R<Response> {
        if self.store.exists() {
            return Err("a vault already exists".into());
        }
        check_password(password)?;
        let rng = &mut OsRandom;
        let mut v = Vault::new(rng).map_err(e)?;
        let pw_slot = v
            .add_password_slot(
                rng,
                Factor::PasswordOnly,
                self.cost,
                password,
                None,
                "password",
            )
            .map_err(e)?;
        let (rc_slot, code) = v.add_recovery_slot(rng, "recovery code").map_err(e)?;
        let bytes = v.to_bytes(rng).map_err(e)?;
        // Test-unlock both slots from the encoded bytes before writing (6.1).
        let parsed = ParsedVault::parse(&bytes).map_err(e)?;
        parsed
            .unlock(
                &pw_slot,
                &Unlock::Password {
                    password,
                    hw_key: None,
                },
            )
            .map_err(e)?;
        parsed
            .unlock(
                &rc_slot,
                &Unlock::Recovery {
                    code: code.as_str(),
                },
            )
            .map_err(e)?;
        self.store.write(&bytes).map_err(|e| e.to_string())?;
        self.store
            .record_generation(&v.vault_id(), v.generation())
            .map_err(|e| e.to_string())?;
        let t = token(rng)?;
        self.store
            .add_client(client_name, ClientScope::Full, &t)
            .map_err(|e| e.to_string())?;
        self.vault = Some(v);
        self.rollback = false;
        Ok(Response::Initialized {
            recovery_code: Zeroizing::new(code.as_str().to_owned()),
            token: t,
        })
    }

    /// Unlock with the first slot the method fits. Rate limited.
    fn prove(&mut self, method: &UnlockMethod) -> R<Vault> {
        if let Some(t) = self.next_attempt
            && Instant::now() < t
        {
            return Err(format!(
                "too many failed attempts; try again in {} s",
                (t - Instant::now()).as_secs() + 1
            ));
        }
        let parsed = ParsedVault::parse(
            &self
                .store
                .read()
                .map_err(|_| "no vault; run `vault init`")?,
        )
        .map_err(e)?;
        let candidates: Vec<KeyslotMeta> = parsed
            .slots()
            .filter(|m| fits(&m.factor, method))
            .cloned()
            .collect();
        if candidates.is_empty() {
            return Err("no slot of that kind is enrolled".into());
        }
        let mut last = String::from("wrong password or factor");
        for meta in &candidates {
            let cred = match self.credential(&meta.factor, method) {
                Ok(c) => c,
                Err(m) => {
                    last = m;
                    continue;
                }
            };
            match parsed.unlock(&meta.id, &cred.as_unlock()) {
                Ok(v) => {
                    self.failures = 0;
                    self.next_attempt = None;
                    self.check_rollback(&v);
                    return Ok(v);
                }
                Err(vault_core::Error::WrongFactor) => {}
                Err(err) => return Err(e(err)),
            }
        }
        self.failures += 1;
        if self.failures > FREE_ATTEMPTS {
            let wait =
                Duration::from_secs(1 << (self.failures - FREE_ATTEMPTS).min(9)).min(MAX_BACKOFF);
            self.next_attempt = Some(Instant::now() + wait);
        }
        Err(last)
    }

    fn check_rollback(&mut self, v: &Vault) {
        let seen = self.store.last_generation(&v.vault_id());
        self.rollback = v.generation() < seen;
        if !self.rollback {
            let _ = self.store.record_generation(&v.vault_id(), v.generation());
        }
    }

    /// Build the credential for one slot, running the hardware factor.
    fn credential(&self, factor: &Factor, method: &UnlockMethod) -> R<Cred> {
        Ok(match (factor, method) {
            (Factor::PasswordOnly, UnlockMethod::Password { password }) => {
                Cred::Password(password.clone(), None)
            }
            (
                Factor::PasswordFido2 {
                    credential_id,
                    rp_id,
                    prf_input,
                    require_uv,
                },
                UnlockMethod::Fido2 { password, pin },
            ) => {
                let dev = self
                    .hw
                    .fido2
                    .as_ref()
                    .ok_or("FIDO2 support is not built in")?;
                let hw = dev.hmac_secret(
                    rp_id,
                    credential_id,
                    &prf_salt(prf_input),
                    pin.as_deref().map(|s| s.as_str()),
                    *require_uv,
                )?;
                Cred::Password(password.clone(), Some(hw))
            }
            (
                Factor::PasswordTpm {
                    blob, pcr_policy, ..
                },
                UnlockMethod::Tpm { password, pin },
            ) => {
                let dev = self.hw.tpm.as_ref().ok_or("TPM support is not built in")?;
                let hw = dev.unseal(
                    blob,
                    pin.as_deref().map(|s| s.as_str()),
                    pcr_policy.is_some(),
                )?;
                Cred::Password(password.clone(), Some(hw))
            }
            (Factor::Recovery, UnlockMethod::Recovery { code }) => Cred::Recovery(code.clone()),
            _ => return Err("that method does not fit this slot".into()),
        })
    }

    fn vault(&mut self) -> R<&mut Vault> {
        self.vault
            .as_mut()
            .ok_or_else(|| "vault is locked; run `vault unlock`".into())
    }

    /// Encode and write the unlocked vault. Refused after a rollback.
    fn save(&mut self) -> R<()> {
        if self.rollback {
            return Err("the vault file is older than one this daemon saw before (possible rollback); writes are refused".into());
        }
        let v = self.vault.as_mut().ok_or("vault is locked")?;
        let bytes = v.to_bytes(&mut OsRandom).map_err(e)?;
        self.store.write(&bytes).map_err(|e| e.to_string())?;
        self.store
            .record_generation(&v.vault_id(), v.generation())
            .map_err(|e| e.to_string())
    }

    /// After adding a slot: re-read the file and unlock it with the new slot.
    fn test_unlock(&self, id: &SlotId, cred: &Unlock<'_>) -> R<()> {
        let parsed =
            ParsedVault::parse(&self.store.read().map_err(|e| e.to_string())?).map_err(e)?;
        parsed
            .unlock(id, cred)
            .map(|_| ())
            .map_err(|err| format!("new slot failed its test unlock: {err}"))
    }

    fn item(&mut self, id: &ItemId) -> R<ItemData> {
        let bytes = self.vault()?.get_item(id).map_err(e)?;
        ItemData::from_bytes(&bytes).map_err(e)
    }

    fn fillable(&mut self, id: &ItemId, origin: &str) -> R<ItemData> {
        let item = self.item(id)?;
        if item.urls.iter().any(|u| may_fill(u, origin)) {
            Ok(item)
        } else {
            Err("this item is not bound to that site".into())
        }
    }

    fn summaries(&mut self, keep: impl Fn(&ItemData) -> bool) -> R<Vec<ItemSummary>> {
        let ids: Vec<ItemId> = self.vault()?.item_ids().copied().collect();
        let mut out = Vec::new();
        for id in ids {
            let it = self.item(&id)?;
            if keep(&it) {
                out.push(ItemSummary {
                    id,
                    title: it.title.clone(),
                    username: it.username.clone(),
                    urls: it.urls.iter().map(|u| u.url.clone()).collect(),
                    has_totp: it.totp.is_some(),
                });
            }
        }
        out.sort_by_key(|s| s.title.to_lowercase());
        Ok(out)
    }

    fn unlocked(&mut self, req: Request) -> R<Response> {
        let rng = &mut OsRandom;
        match req {
            Request::ListSlots => {
                let v = self.vault()?;
                Ok(Response::Slots(
                    v.slots()
                        .map(|m| SlotInfo {
                            id: m.id,
                            kind: kind(&m.factor).into(),
                            label: v.slot_label(&m.id).unwrap_or("").into(),
                        })
                        .collect(),
                ))
            }
            Request::AddPasswordSlot { password, label } => {
                check_password(&password)?;
                let cost = self.cost;
                let id = self
                    .vault()?
                    .add_password_slot(rng, Factor::PasswordOnly, cost, &password, None, &label)
                    .map_err(e)?;
                self.save()?;
                self.test_unlock(
                    &id,
                    &Unlock::Password {
                        password: &password,
                        hw_key: None,
                    },
                )?;
                Ok(Response::SlotAdded {
                    id,
                    recovery_code: None,
                })
            }
            Request::AddFido2Slot {
                password,
                pin,
                require_uv,
                label,
            } => {
                check_password(&password)?;
                self.vault()?;
                let dev = self
                    .hw
                    .fido2
                    .as_ref()
                    .ok_or("FIDO2 support is not built in")?;
                let pin = pin.as_deref().map(|s| s.as_str());
                let credential_id = dev.enroll(RP_ID, pin, require_uv)?;
                let mut prf_input = [0u8; 32];
                rng.fill(&mut prf_input).map_err(e)?;
                let hw = dev.hmac_secret(
                    RP_ID,
                    &credential_id,
                    &prf_salt(&prf_input),
                    pin,
                    require_uv,
                )?;
                let factor = Factor::PasswordFido2 {
                    credential_id,
                    rp_id: RP_ID.into(),
                    prf_input,
                    require_uv,
                };
                let cost = self.cost;
                let id = self
                    .vault()?
                    .add_password_slot(rng, factor, cost, &password, Some(&hw), &label)
                    .map_err(e)?;
                self.save()?;
                self.test_unlock(
                    &id,
                    &Unlock::Password {
                        password: &password,
                        hw_key: Some(&hw),
                    },
                )?;
                Ok(Response::SlotAdded {
                    id,
                    recovery_code: None,
                })
            }
            Request::AddTpmSlot {
                password,
                pin,
                bind_pcr7,
                label,
            } => {
                check_password(&password)?;
                self.vault()?;
                let dev = self.hw.tpm.as_ref().ok_or("TPM support is not built in")?;
                let pin = pin.as_deref().map(|s| s.as_str());
                let mut secret = Zeroizing::new([0u8; 32]);
                rng.fill(&mut secret[..]).map_err(e)?;
                let blob = dev.seal(&secret, pin, bind_pcr7)?;
                let hw = dev.unseal(&blob, pin, bind_pcr7)?;
                if !hw.ct_eq(&secret) {
                    return Err("TPM returned a different secret than it sealed".into());
                }
                let factor = Factor::PasswordTpm {
                    blob,
                    pcr_policy: bind_pcr7.then(|| PcrPolicy {
                        bank: 1,
                        pcrs: vec![7],
                    }),
                    has_pin: pin.is_some_and(|p| !p.is_empty()),
                };
                let cost = self.cost;
                let id = self
                    .vault()?
                    .add_password_slot(rng, factor, cost, &password, Some(&hw), &label)
                    .map_err(e)?;
                self.save()?;
                self.test_unlock(
                    &id,
                    &Unlock::Password {
                        password: &password,
                        hw_key: Some(&hw),
                    },
                )?;
                Ok(Response::SlotAdded {
                    id,
                    recovery_code: None,
                })
            }
            Request::AddRecoverySlot { label } => {
                let (id, code) = self.vault()?.add_recovery_slot(rng, &label).map_err(e)?;
                self.save()?;
                self.test_unlock(
                    &id,
                    &Unlock::Recovery {
                        code: code.as_str(),
                    },
                )?;
                Ok(Response::SlotAdded {
                    id,
                    recovery_code: Some(Zeroizing::new(code.as_str().to_owned())),
                })
            }
            Request::RemoveSlot { slot } => {
                self.vault()?.remove_slot(&slot).map_err(e)?;
                self.save()?;
                Ok(Response::Ok)
            }
            Request::Revoke { keep } => {
                let metas: Vec<KeyslotMeta> = self.vault()?.slots().cloned().collect();
                let mut creds = Vec::with_capacity(keep.len());
                for (id, method) in &keep {
                    let meta = metas.iter().find(|m| &m.id == id).ok_or("no such slot")?;
                    creds.push((*id, self.credential(&meta.factor, method)?));
                }
                let pairs: Vec<(SlotId, Unlock<'_>)> =
                    creds.iter().map(|(id, c)| (*id, c.as_unlock())).collect();
                let v = self.vault.as_mut().ok_or("vault is locked")?;
                let removed = v.revoke(rng, &pairs).map_err(e)?;
                drop(pairs);
                self.save()?;
                Ok(Response::Revoked { removed })
            }
            Request::ListItems => Ok(Response::Items(self.summaries(|_| true)?)),
            Request::GetItem { id } => Ok(Response::Item {
                item: self.item(&id)?,
                id,
            }),
            Request::PutItem { id, mut item } => {
                let t = now();
                let id = match id {
                    Some(id) => {
                        item.created = self.item(&id)?.created;
                        id
                    }
                    None => {
                        item.created = t;
                        self.vault()?.new_item_id(rng).map_err(e)?
                    }
                };
                item.modified = t;
                self.vault()?
                    .put_item(rng, &id, &item.to_bytes())
                    .map_err(e)?;
                self.save()?;
                Ok(Response::ItemSaved { id })
            }
            Request::DeleteItem { id } => {
                self.vault()?.remove_item(&id).map_err(e)?;
                self.save()?;
                Ok(Response::Ok)
            }
            Request::FindForOrigin { origin } => {
                Ok(Response::Items(self.summaries(|it| {
                    it.urls.iter().any(|u| may_fill(u, &origin))
                })?))
            }
            Request::GetForFill { id, origin } => Ok(Response::Item {
                item: self.fillable(&id, &origin)?,
                id,
            }),
            Request::Totp { id } => totp(&self.item(&id)?),
            Request::TotpForFill { id, origin } => totp(&self.fillable(&id, &origin)?),
            Request::Import { format, data } => {
                let t = now();
                let items = match format {
                    ImportFormat::BitwardenJson => {
                        vault_import::bitwarden_json(&data, t).map(|(i, _)| i)
                    }
                    ImportFormat::BrowserCsv => vault_import::browser_csv(&data, t),
                }
                .map_err(|err| err.to_string())?;
                let v = self.vault()?;
                for item in &items {
                    let id = v.new_item_id(rng).map_err(e)?;
                    v.put_item(rng, &id, &item.to_bytes()).map_err(e)?;
                }
                self.save()?;
                Ok(Response::Imported(items.len()))
            }
            Request::Status
            | Request::Init { .. }
            | Request::Pair { .. }
            | Request::Unlock { .. }
            | Request::Lock
            | Request::Generate { .. } => {
                unreachable!("handled in dispatch")
            }
        }
    }
}

fn totp(item: &ItemData) -> R<Response> {
    let cfg = item.totp.as_ref().ok_or("this item has no TOTP seed")?;
    let t = now();
    Ok(Response::Totp {
        code: Zeroizing::new(cfg.code_at(t).map_err(e)?),
        remaining: cfg.remaining(t),
    })
}

fn fits(f: &Factor, m: &UnlockMethod) -> bool {
    matches!(
        (f, m),
        (Factor::PasswordOnly, UnlockMethod::Password { .. })
            | (Factor::PasswordFido2 { .. }, UnlockMethod::Fido2 { .. })
            | (Factor::PasswordTpm { .. }, UnlockMethod::Tpm { .. })
            | (Factor::Recovery, UnlockMethod::Recovery { .. })
    )
}

fn check_password(p: &str) -> R<()> {
    if p.chars().count() < 8 {
        Err("the password must be at least 8 characters".into())
    } else {
        Ok(())
    }
}
