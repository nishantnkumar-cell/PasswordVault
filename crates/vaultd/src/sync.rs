//! Folder sync: the vault is merged with a copy in a folder that OneDrive,
//! Google Drive or Dropbox keeps in step across devices (docs/sync.md). The
//! local file stays the daemon's own; the synced copy is read when it
//! changes and rewritten after every save.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::store::write_atomic;

/// How often an unlocked daemon looks for changes.
pub const CHECK_EVERY: Duration = Duration::from_secs(5);
/// Every this many checks, read every copy even if its time and length look
/// unchanged: some file systems keep times to the second or coarser, and
/// padding keeps most writes the same length.
const FULL_EVERY: u32 = 12;

/// A file's modified time and length: when either moves, read it again.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stamp {
    modified: Option<SystemTime>,
    len: u64,
}

fn stamp(path: &Path) -> Option<Stamp> {
    let m = fs::metadata(path).ok()?;
    m.is_file().then(|| Stamp {
        modified: m.modified().ok(),
        len: m.len(),
    })
}

/// A copy that changed since it was last read or written.
pub struct Changed {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub stamp: Stamp,
}

pub struct Folder {
    path: PathBuf,
    seen: HashMap<PathBuf, Stamp>,
    last_check: Option<Instant>,
    checks: u32,
}

impl Folder {
    pub fn new(path: PathBuf) -> Folder {
        Folder {
            path,
            seen: HashMap::new(),
            last_check: None,
            checks: 0,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_main(&self, path: &Path) -> bool {
        path == self.path
    }

    pub fn exists(&self) -> bool {
        stamp(&self.path).is_some()
    }

    /// The synced copy, then any other file next to it whose name starts
    /// the same and has the same extension: the copies cloud services make
    /// when two devices write at once ("vault (1).svault",
    /// "vault-LAPTOP.svault", "vault (conflicted copy 2026-10-20).svault").
    pub fn copies(&self) -> Vec<PathBuf> {
        let mut out = vec![self.path.clone()];
        let (Some(dir), Some(stem)) = (self.path.parent(), self.path.file_stem()) else {
            return out;
        };
        let stem = stem.to_string_lossy();
        let ext = self.path.extension();
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        let Ok(entries) = fs::read_dir(dir) else {
            return out;
        };
        let mut others: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension() == ext
                    && p.file_name() != self.path.file_name()
                    && p.file_stem()
                        .is_some_and(|s| s.to_string_lossy().starts_with(&*stem))
            })
            .collect();
        others.sort();
        out.extend(others);
        out
    }

    /// Whether it is time to look for changes again, and if so whether to
    /// read every copy (see [`Folder::changed`]).
    pub fn due(&mut self) -> Option<bool> {
        if self.last_check.is_some_and(|t| t.elapsed() < CHECK_EVERY) {
            return None;
        }
        self.last_check = Some(Instant::now());
        self.checks = self.checks.wrapping_add(1);
        Some(self.checks.is_multiple_of(FULL_EVERY))
    }

    /// Every copy that changed since it was last read or written, or every
    /// copy with `all`.
    pub fn changed(&self, all: bool) -> Vec<Changed> {
        self.copies()
            .into_iter()
            .filter_map(|path| {
                let stamp = stamp(&path)?;
                if !all && self.seen.get(&path) == Some(&stamp) {
                    return None;
                }
                let bytes = fs::read(&path).ok()?;
                Some(Changed { path, bytes, stamp })
            })
            .collect()
    }

    /// Note that a copy was read as of `stamp`.
    pub fn mark(&mut self, path: PathBuf, stamp: Stamp) {
        self.seen.insert(path, stamp);
    }

    /// Replace the synced copy.
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        write_atomic(&self.path, bytes)?;
        if let Some(s) = stamp(&self.path) {
            self.seen.insert(self.path.clone(), s);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_cloud_conflict_copies_and_changes() {
        let dir = std::env::temp_dir().join(format!("vaultd-sync-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let main = dir.join("vault.svault");
        let mut f = Folder::new(main.clone());
        assert!(f.changed(false).is_empty());

        f.write(b"one").unwrap();
        assert!(f.changed(false).is_empty());
        assert_eq!(f.changed(true).len(), 1);

        for name in [
            "vault (1).svault",
            "vault-LAPTOP.svault",
            "other.svault",
            "vault.tmp",
        ] {
            fs::write(dir.join(name), b"x").unwrap();
        }
        let names: Vec<_> = f
            .changed(false)
            .into_iter()
            .map(|c| c.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["vault (1).svault", "vault-LAPTOP.svault"]);

        fs::write(&main, b"longer").unwrap();
        let c = f.changed(false);
        assert!(f.is_main(&c[0].path));
        assert_eq!(c[0].bytes, b"longer");
        fs::remove_dir_all(&dir).unwrap();
    }
}
