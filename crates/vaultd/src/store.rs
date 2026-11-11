//! Vault file and daemon state on disk (format.md sections 6.5 and 6.6).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vault_ipc::{ActivityEntry, ClientScope};

/// Paths owned by the daemon.
pub struct Store {
    vault: PathBuf,
    state_dir: PathBuf,
    _lock: File,
}

/// Most snapshots kept.
pub const KEEP_SNAPSHOTS: usize = 20;
/// Least time between two automatic snapshots.
pub const AUTO_SNAPSHOT_GAP: std::time::Duration = std::time::Duration::from_secs(600);

/// Most entries kept in the activity log.
pub const KEEP_ACTIVITY: usize = 2000;

/// A kept copy of the vault file.
pub struct SnapshotFile {
    pub name: String,
    pub taken: u64,
    pub size: u64,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Serialize, Deserialize, Default)]
struct Generations(Vec<([u8; 16], u64)>);

#[derive(Serialize, Deserialize, Default)]
struct Clients(Vec<(String, ClientScope, [u8; 32])>);

#[derive(Serialize, Deserialize, Default)]
struct SyncPath(Option<String>);

#[derive(Serialize, Deserialize, Default)]
struct QuickUnlock(u32);

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

    /// Write atomically: temp file, fsync, rename, fsync directory. The
    /// file being replaced is kept as a snapshot first (at most one every
    /// [`AUTO_SNAPSHOT_GAP`]).
    pub fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let _ = self.snapshot("auto");
        write_atomic(&self.vault, bytes)
    }

    fn snapshot_dir(&self) -> PathBuf {
        self.state_dir.join("snapshots")
    }

    /// Keep a copy of the vault file as it is now, before something changes
    /// it. `reason` is a short word (`auto`, `merge`, `revoke`, `import`,
    /// `remove-slot`). The reasons `auto` and `merge` are rate limited;
    /// the others are always kept. A copy identical to the newest one is not
    /// kept again, and only the newest [`KEEP_SNAPSHOTS`] stay.
    pub fn snapshot(&self, reason: &str) -> io::Result<()> {
        let bytes = match fs::read(&self.vault) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let dir = self.snapshot_dir();
        fs::create_dir_all(&dir)?;
        let list = self.snapshots();
        if let Some(newest) = list.last() {
            let rate_limited = matches!(reason, "auto" | "merge");
            if rate_limited && unix_now().saturating_sub(newest.taken) < AUTO_SNAPSHOT_GAP.as_secs()
            {
                return Ok(());
            }
            if fs::read(dir.join(&newest.name)).is_ok_and(|b| b == bytes) {
                return Ok(());
            }
        }
        let reason: String = reason
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(16)
            .collect();
        let mut taken = unix_now();
        // Two snapshots in one second must still sort in order.
        if let Some(newest) = list.last() {
            taken = taken.max(newest.taken + 1);
        }
        write_atomic(&dir.join(format!("{taken:012}-{reason}.svault")), &bytes)?;
        let mut all = self.snapshots();
        while all.len() > KEEP_SNAPSHOTS {
            let old = all.remove(0);
            let _ = fs::remove_file(dir.join(old.name));
        }
        Ok(())
    }

    /// The snapshots, oldest first.
    pub fn snapshots(&self) -> Vec<SnapshotFile> {
        let mut out: Vec<SnapshotFile> = fs::read_dir(self.snapshot_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let taken = name.split('-').next()?.parse::<u64>().ok()?;
                name.ends_with(".svault").then_some(())?;
                Some(SnapshotFile {
                    taken,
                    size: e.metadata().ok()?.len(),
                    name,
                })
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// A snapshot's bytes, by the name `snapshots` gave (or the newest when
    /// `name` is `None`). Nothing outside the snapshot folder can be named.
    pub fn read_snapshot(&self, name: &str) -> io::Result<Vec<u8>> {
        let found = self
            .snapshots()
            .into_iter()
            .find(|s| s.name == name || s.name.trim_end_matches(".svault") == name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such snapshot"))?;
        fs::read(self.snapshot_dir().join(found.name))
    }

    fn activity_path(&self) -> PathBuf {
        self.state_dir.join("activity.log")
    }

    /// Add a line to the activity log: when, what, who, and whether it
    /// worked. Never holds a secret or an item title. The log keeps
    /// roughly the last [`KEEP_ACTIVITY`] entries.
    pub fn log_activity(&self, event: &str, who: &str, ok: bool) {
        fn clean(s: &str) -> String {
            s.chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .take(80)
                .collect()
        }
        let line = format!(
            "{}\t{}\t{}\t{}\n",
            unix_now(),
            clean(event),
            clean(who),
            u8::from(ok)
        );
        let path = self.activity_path();
        let _ = (|| -> io::Result<()> {
            let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
            f.write_all(line.as_bytes())?;
            if f.metadata()?.len() > (KEEP_ACTIVITY as u64) * 200 {
                drop(f);
                let text = fs::read_to_string(&path)?;
                let lines: Vec<&str> = text.lines().collect();
                let keep = lines[lines.len().saturating_sub(KEEP_ACTIVITY / 2)..].join("\n");
                write_atomic(&path, format!("{keep}\n").as_bytes())?;
            }
            Ok(())
        })();
    }

    /// The newest `limit` activity entries, newest first.
    pub fn activity(&self, limit: usize) -> Vec<ActivityEntry> {
        let text = fs::read_to_string(self.activity_path()).unwrap_or_default();
        text.lines()
            .rev()
            .filter_map(|l| {
                let mut p = l.split('\t');
                Some(ActivityEntry {
                    time: p.next()?.parse().ok()?,
                    event: p.next()?.to_owned(),
                    who: p.next()?.to_owned(),
                    ok: p.next()? == "1",
                })
            })
            .take(limit)
            .collect()
    }

    /// The vault file as it is on disk now.
    pub fn read_vault_file(&self) -> io::Result<Vec<u8>> {
        fs::read(&self.vault)
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
        self.client(token).map(|(_, s)| s)
    }

    /// The name and scope of a paired client's token, if it is known.
    pub fn client(&self, token: &[u8; 32]) -> Option<(String, ClientScope)> {
        let h: [u8; 32] = Sha256::digest(token).into();
        // Comparing hashes hides timing on the token itself.
        self.load::<Clients>("clients")
            .0
            .into_iter()
            .find(|(_, _, t)| *t == h)
            .map(|(n, s, _)| (n, s))
    }

    /// This installation's device ID for merge clocks, made on first use.
    pub fn device_id(&self) -> io::Result<u64> {
        let path = self.state_dir.join("device");
        if let Ok(b) = fs::read(&path)
            && let Ok(b) = <[u8; 8]>::try_from(b.as_slice())
        {
            return Ok(u64::from_le_bytes(b));
        }
        let mut b = [0u8; 8];
        vault_core::SecureRandom::fill(&mut vault_core::OsRandom, &mut b)
            .map_err(io::Error::other)?;
        write_atomic(&path, &b)?;
        Ok(u64::from_le_bytes(b))
    }

    /// The synced copy's path, if sync is on.
    pub fn sync_path(&self) -> Option<PathBuf> {
        self.load::<SyncPath>("sync").0.map(PathBuf::from)
    }

    pub fn set_sync_path(&self, path: Option<&Path>) -> io::Result<()> {
        let p = path.map(|p| p.to_string_lossy().into_owned());
        self.save("sync", &SyncPath(p))
    }

    /// Hours quick unlock lasts after a full unlock; 0 is off.
    pub fn quick_unlock_hours(&self) -> u32 {
        self.load::<QuickUnlock>("quick-unlock").0
    }

    pub fn set_quick_unlock_hours(&self, hours: u32) -> io::Result<()> {
        self.save("quick-unlock", &QuickUnlock(hours))
    }

    /// The local vault file.
    pub fn vault_path(&self) -> &Path {
        &self.vault
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
