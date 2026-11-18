//! Cloud sync on the phone (docs/cloud-sync.md): join with a one-time link
//! from a computer, then keep the vault merged with the server's copy. The
//! app has no helper program, so these calls do the network part
//! themselves, blocking; the apps run them off the main thread.
//!
//! The app keeps this device's access as one opaque text (the same
//! `key=value` text `vault-sync` keeps in `device.conf`), in the Keychain or
//! Android Keystore-backed storage, since it holds the device token.

use vault_cloud::{Fetched, JoinLink, Mailbox, OwnCa, Saved, Server};
use vault_core::OsRandom;
use vault_ipc::CloudDevice;

use crate::{MobileError, R, VaultSession, invalid};

impl From<vault_cloud::Error> for MobileError {
    fn from(e: vault_cloud::Error) -> MobileError {
        invalid(e.0)
    }
}

fn device(access: &str) -> R<CloudDevice> {
    CloudDevice::from_text(access).ok_or_else(|| {
        invalid("this device's cloud sync access is damaged; join again with a new link")
    })
}

/// What joining gave.
#[derive(uniffi::Record)]
pub struct CloudJoin {
    /// This device's access, to keep in secure storage and pass back.
    pub access: String,
    /// The server's address, to show.
    pub server: String,
    /// The vault file on the server, if one is there yet.
    pub file: Option<Vec<u8>>,
    /// The version of that file, for the first [`VaultSession::cloud_sync`].
    pub version: Option<u64>,
}

/// Join cloud sync with a link from a computer (`vault cloud link`, or Add a
/// device on the desktop app's Sync page). `name` is how this device shows
/// in the device list.
#[uniffi::export]
pub fn cloud_join(link: String, name: String) -> R<CloudJoin> {
    let link = JoinLink::parse(&link)?;
    if link.shared {
        return Err(invalid(
            "this is an invite to a shared collection, which phones cannot open yet; use the link from your computer's Sync page (Add a device)",
        ));
    }
    let ca = match &link.fingerprint {
        Some(f) => Some(OwnCa::fetch(&link.server, f)?.pem().to_owned()),
        None => None,
    };
    let server = Server::with_ca(&link.server, ca.as_deref())?;
    server.info()?;
    let token = vault_cloud::random_token()?;
    let id = server.join(&link, &token, &name)?;
    let d = CloudDevice {
        server: link.server.clone(),
        mailbox: link.mailbox.clone(),
        device: id,
        token,
        ca_cert: ca,
    };
    let (file, version) = match Mailbox::from_device(&d)?.get(None)? {
        Fetched::File(v, bytes) => (Some(bytes), Some(v)),
        Fetched::Empty(v) => (None, Some(v)),
        Fetched::Unchanged => (None, None),
    };
    Ok(CloudJoin {
        access: d.to_text().to_string(),
        server: link.server,
        file,
        version,
    })
}

/// The server's address in `access`, to show.
#[uniffi::export]
pub fn cloud_server(access: String) -> Option<String> {
    CloudDevice::from_text(&access).map(|d| d.server)
}

/// Stop cloud sync on this device: delete its access on the server. The
/// vault on this device and on the server stay as they are.
#[uniffi::export]
pub fn cloud_leave(access: String) -> R<()> {
    let d = device(&access)?;
    Ok(Mailbox::from_device(&d)?.remove_device(&d.device)?)
}

/// What a cloud sync did.
#[derive(uniffi::Record)]
pub struct CloudSync {
    /// The server's version now; pass it to the next sync.
    pub version: u64,
    /// This device's vault changed: save it and reload the list.
    pub changed: bool,
    /// Items edited on two devices at once (both versions kept).
    pub conflicts: u32,
}

#[uniffi::export]
impl VaultSession {
    /// Merge with the server's copy and upload the result when the server
    /// lacks something. `known` is the version the last sync returned (the
    /// server then answers "unchanged" without sending the file); `dirty`
    /// says this device changed since then. A copy re-keyed on another
    /// device needs `password` (as [`VaultSession::merge`]).
    pub fn cloud_sync(
        &self,
        access: String,
        known: Option<u64>,
        dirty: bool,
        password: Option<String>,
    ) -> R<CloudSync> {
        let d = device(&access)?;
        let m = Mailbox::from_device(&d)?;
        let mut known = known;
        let mut changed = false;
        let mut conflicts = 0;
        // Another device can save between our read and write; then read
        // again and merge that too.
        for _ in 0..4 {
            let (base, upload) = match m.get(known)? {
                Fetched::Unchanged => match known {
                    Some(v) if dirty || changed => (v, true),
                    Some(v) => {
                        return Ok(CloudSync {
                            version: v,
                            changed,
                            conflicts,
                        });
                    }
                    None => return Err(invalid("the server answered without a version")),
                },
                Fetched::Empty(v) => (v, true),
                Fetched::File(v, bytes) => {
                    let r = self.merge(bytes, password.clone())?;
                    changed |= r.changed;
                    conflicts += r.conflicts;
                    (v, r.changed || r.other_behind || dirty)
                }
            };
            if !upload {
                return Ok(CloudSync {
                    version: base,
                    changed,
                    conflicts,
                });
            }
            let file = self.lock().to_bytes(&mut OsRandom)?;
            match m.put(base, &file)? {
                Saved::Saved(v) => {
                    return Ok(CloudSync {
                        version: v,
                        changed,
                        conflicts,
                    });
                }
                Saved::Conflict(_) => known = None,
            }
        }
        Err(invalid(
            "other devices kept saving at the same moment; try again in a minute",
        ))
    }
}
