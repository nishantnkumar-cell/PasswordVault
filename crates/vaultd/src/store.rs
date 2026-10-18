//! Vault file and daemon state on disk (format.md sections 6.5 and 6.6).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vault_ipc::ClientScope;

/// Paths owned by the daemon.
pub struct Store {
    vault: PathBuf,
    state_dir: PathBuf,
    _lock: File,
}

#[derive(Serialize, Deserialize, Default)]
struct Generations(Vec<([u8; 16], u64)>);

#[derive(Serialize, Deserialize, Default)]
struct Clients(Vec<(String, ClientScope, [u8; 32])>);

impl Store {
    /// Open the store, taking an exclusive lock so only one daemon writes.
    pub fn open(vault: PathBuf, state_dir: PathBuf) -> io::Result<Store> {
        fs::create_dir_all(&state_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700))?;
        }
        if let Some(dir) = vault.parent() {
            fs::create_dir_all(dir)?;
        }
        let lock = private()
            .truncate(false)
            .open(state_dir.join("vaultd.lock"))?;
        lock.try_lock()
            .map_err(|_| io::Error::other("another vaultd holds the lock"))?;
        Ok(Store {
            vault,
            state_dir,
            _lock: lock,
        })
    }

    pub fn exists(&self) -> bool {
        self.vault.exists()
    }

    pub fn read(&self) -> io::Result<Vec<u8>> {
        fs::read(&self.vault)
    }

    /// Write atomically: temp file, fsync, rename, fsync directory.
    pub fn write(&self, bytes: &[u8]) -> io::Result<()> {
        write_atomic(&self.vault, bytes)
    }

    /// Last generation seen for this vault.
    pub fn last_generation(&self, vault_id: &[u8; 16]) -> u64 {
        self.load::<Generations>("generations")
            .0
            .iter()
            .find(|(id, _)| id == vault_id)
            .map_or(0, |(_, g)| *g)
    }

    pub fn record_generation(&self, vault_id: &[u8; 16], generation: u64) -> io::Result<()> {
        let mut g = self.load::<Generations>("generations");
        g.0.retain(|(id, _)| id != vault_id);
        g.0.push((*vault_id, generation));
        self.save("generations", &g)
    }

    /// Store a paired client's token hash.
    pub fn add_client(&self, name: &str, scope: ClientScope, token: &[u8; 32]) -> io::Result<()> {
        let mut c = self.load::<Clients>("clients");
        c.0.push((name.to_owned(), scope, Sha256::digest(token).into()));
        self.save("clients", &c)
    }

    /// The scope of a paired client's token, if it is known.
    pub fn client_scope(&self, token: &[u8; 32]) -> Option<ClientScope> {
        let h: [u8; 32] = Sha256::digest(token).into();
        // Comparing hashes hides timing on the token itself.
        self.load::<Clients>("clients")
            .0
            .iter()
            .find(|(_, _, t)| *t == h)
            .map(|(_, s, _)| *s)
    }

    pub fn forget_clients(&self) -> io::Result<()> {
        self.save("clients", &Clients::default())
    }

    fn load<T: for<'a> Deserialize<'a> + Default>(&self, name: &str) -> T {
        fs::read(self.state_dir.join(name))
            .ok()
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    fn save<T: Serialize>(&self, name: &str, v: &T) -> io::Result<()> {
        write_atomic(
            &self.state_dir.join(name),
            &postcard::to_allocvec(v).map_err(io::Error::other)?,
        )
    }
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = path.with_extension("tmp");
    {
        let mut f = private().truncate(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    // Windows cannot open a directory as a file; its rename is already durable
    // once the file was flushed.
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Create-or-open for writing, readable only by this user (0600 on Unix; on
/// Windows the profile directory's ACL already does this).
fn private() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.create(true).write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o
}
