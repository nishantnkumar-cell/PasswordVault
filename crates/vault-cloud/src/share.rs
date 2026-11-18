//! Shared collections over cloud sync (docs/sharing.md), for `vault share`
//! and the desktop app's Sharing page. Each collection has a mailbox of its
//! own on the owner's sync server; each member gets one access token for it,
//! shared by all of that member's devices, named after their identity so the
//! owner can cut it off when removing them.

use vault_ipc::{CloudDevice, CollectionInfo, Request, Response, Secret};

use crate::flows::{Call, info, settings};
use crate::{Fetched, JoinLink, Mailbox, OwnCa, Result, Server, err};

fn ask(call: &mut Call<'_>, r: Request) -> Result<Response> {
    match call(r)? {
        Response::Error(m) => Err(err(m)),
        other => Ok(other),
    }
}

fn collections_of(r: Response) -> Result<Vec<CollectionInfo>> {
    match r {
        Response::Collections(c) => Ok(c),
        _ => Err(err("unexpected answer from vaultd")),
    }
}

/// This person's sharing card: name, card text, safety code, fingerprint.
/// `name` makes the identity if there is none yet.
pub struct Card {
    pub name: String,
    pub card: String,
    pub safety: String,
    pub fingerprint: [u8; 32],
}

pub fn card(call: &mut Call<'_>, name: Option<String>) -> Result<Card> {
    match ask(call, Request::SharingIdentity { name })? {
        Response::SharingCard {
            name,
            card,
            safety,
            fingerprint,
        } => Ok(Card {
            name,
            card,
            safety,
            fingerprint,
        }),
        _ => Err(err("unexpected answer from vaultd")),
    }
}

/// The name a member's access has on the server.
pub fn device_name(fingerprint: &[u8; 32]) -> String {
    format!(
        "member-{}",
        data_encoding::HEXLOWER.encode(&fingerprint[..8])
    )
}

pub fn list(call: &mut Call<'_>) -> Result<Vec<CollectionInfo>> {
    collections_of(ask(call, Request::Collections)?)
}

/// Make a shared collection on this vault's cloud sync server, with this
/// person as its owner.
pub fn create(call: &mut Call<'_>, name: &str) -> Result<Vec<CollectionInfo>> {
    let me = card(call, None)?;
    let i = info(call)?;
    let s = settings(&i)?;
    let server = Server::with_ca(&s.server, s.ca_cert.as_deref())?;
    let mailbox = crate::random_mailbox()?;
    let token = crate::random_token()?;
    let device = server.create(
        &mailbox,
        &s.admin_key,
        &token,
        &device_name(&me.fingerprint),
    )?;
    collections_of(ask(
        call,
        Request::CollectionCreate {
            name: name.to_owned(),
            device: CloudDevice {
                server: s.server.clone(),
                mailbox,
                device,
                token,
                ca_cert: s.ca_cert.clone(),
            },
        },
    )?)
}

fn mine(c: &CollectionInfo) -> Result<&CloudDevice> {
    c.device
        .as_ref()
        .ok_or_else(|| err("this shared collection has no server access on this device"))
}

/// Add the person whose sharing card this is, and make a one-time invite
/// link for them (with the minutes it is valid). Owner only.
pub fn add(
    call: &mut Call<'_>,
    id: [u8; 16],
    name: &str,
    card_text: &str,
) -> Result<(Secret, u64, Vec<CollectionInfo>)> {
    let list = collections_of(ask(
        call,
        Request::CollectionAddMember {
            id,
            name: name.to_owned(),
            card: card_text.to_owned(),
        },
    )?)?;
    let c = list
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(|| err("no such shared collection"))?;
    let (link, minutes) = invite(c)?;
    Ok((link, minutes, list))
}

/// A one-time invite link to collection `c` (owner only), and the minutes
/// it is valid. Only someone the owner added can open what it downloads.
pub fn invite(c: &CollectionInfo) -> Result<(Secret, u64)> {
    if !c.owner {
        return Err(err(
            "only the person who made this shared collection can invite people",
        ));
    }
    let d = mine(c)?;
    let t = Mailbox::from_device(d)?.ticket()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let link = JoinLink {
        server: d.server.clone(),
        mailbox: d.mailbox.clone(),
        ticket: t.ticket,
        fingerprint: d
            .ca_cert
            .as_deref()
            .and_then(|p| OwnCa::from_pem(p).ok())
            .map(|c| c.fingerprint()),
        shared: true,
    };
    Ok((link.to_link(), t.expires.saturating_sub(now).div_ceil(60)))
}

/// Join a shared collection with an invite link. The owner must have added
/// this person's card first.
pub fn join(call: &mut Call<'_>, link: &str) -> Result<Vec<CollectionInfo>> {
    let link = JoinLink::parse(link)?;
    if !link.shared {
        return Err(err(
            "this is a link to join your own vault on another device, not an invite to a shared collection",
        ));
    }
    let me = card(call, None)?;
    let ca_pem = match &link.fingerprint {
        Some(f) => Some(OwnCa::fetch(&link.server, f)?.pem().to_owned()),
        None => None,
    };
    let server = Server::with_ca(&link.server, ca_pem.as_deref())?;
    let token = crate::random_token()?;
    let device = server.join(&link, &token, &device_name(&me.fingerprint))?;
    let access = CloudDevice {
        server: link.server.clone(),
        mailbox: link.mailbox.clone(),
        device,
        token,
        ca_cert: ca_pem,
    };
    let file = match Mailbox::from_device(&access)?.get(None)? {
        Fetched::File(_, bytes) => bytes,
        _ => {
            return Err(err(
                "the shared collection is not on the server yet; ask its owner to open the app, then try again with a new link",
            ));
        }
    };
    collections_of(ask(
        call,
        Request::CollectionJoin {
            device: access,
            file,
        },
    )?)
}

/// Remove a member, rotate the collection's key, and cut off that member's
/// access on the server, along with any access that is not a current
/// member's. Owner only.
pub fn remove(call: &mut Call<'_>, id: [u8; 16], member: [u8; 32]) -> Result<Vec<CollectionInfo>> {
    let list = collections_of(ask(call, Request::CollectionRemoveMember { id, member })?)?;
    let c = list
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(|| err("no such shared collection"))?;
    let m = Mailbox::from_device(mine(c)?)?;
    // Every access that is not a current member's goes: the removed
    // person's, and any other they may have made with it.
    let keep: Vec<String> = c
        .members
        .iter()
        .map(|x| device_name(&x.fingerprint))
        .collect();
    debug_assert!(!keep.contains(&device_name(&member)));
    for d in m.devices()? {
        if !d.current && !keep.contains(&d.name) {
            m.remove_device(&d.id)?;
        }
    }
    Ok(list)
}

/// Stop using a shared collection. For its owner this deletes it from the
/// server for everyone; a member only gives up their own access.
pub fn leave(call: &mut Call<'_>, id: [u8; 16]) -> Result<Vec<CollectionInfo>> {
    let list = self::list(call)?;
    let c = list
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(|| err("no such shared collection"))?;
    if let Ok(d) = mine(c) {
        let m = Mailbox::from_device(d)?;
        // Best effort: the server may already have removed this access.
        let _ = if c.owner {
            m.delete()
        } else {
            m.remove_device(&d.device)
        };
    }
    collections_of(ask(call, Request::CollectionLeave { id })?)
}
