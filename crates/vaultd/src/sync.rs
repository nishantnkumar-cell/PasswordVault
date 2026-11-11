//! Folder sync: the vault is merged with a copy in a folder that OneDrive,
//! Google Drive or Dropbox keeps in step across devices (docs/sync.md). The
//! local file stays the daemon's own; the synced copy is read when it
//! changes and rewritten after every save.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::store::write_atomic;

/// How often an unlocked daemon looks for changes.
pub const CHECK_EVERY: Duration = Duration::from_secs(5);
/// Every this many checks, read every copy even if its time and length look
/// unchanged: some file systems keep times to the second or coarser, and
/// padding keeps most writes the same length.
const FULL_EVERY: u32 = 12;

/// Largest vault copy read from the sync folder. A vault holds text items,
/// so even a very large one is a few MiB; this leaves plenty of room.
pub const MAX_COPY_BYTES: u64 = 64 << 20;
/// Most conflict copies looked at besides the synced copy itself. Cloud
/// services make one per clash, so more than this is a sign of something
/// else writing into the folder; the rest are ignored (by name order).
pub const MAX_OTHER_COPIES: usize = 16;
/// Most bytes read from the folder in one check, all copies together.
pub const MAX_CHECK_BYTES: u64 = 256 << 20;

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
    /// Empty when `too_big`.
    pub bytes: Vec<u8>,
    pub stamp: Stamp,
    /// Larger than [`MAX_COPY_BYTES`], so not read.
    pub too_big: bool,
}

/// Read at most `cap` bytes of `path`; `None` if it is longer (even if it
/// grew after its length was checked) or cannot be read.
fn read_capped(path: &Path, cap: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(cap + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= cap).then_some(bytes)
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
        others.truncate(MAX_OTHER_COPIES);
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
    ///
    /// At most [`MAX_OTHER_COPIES`] conflict copies are looked at, a copy
    /// over [`MAX_COPY_BYTES`] comes back `too_big` and unread, and once
    /// [`MAX_CHECK_BYTES`] have been read the rest wait for the next check.
    pub fn changed(&self, all: bool) -> Vec<Changed> {
        let mut out = Vec::new();
        let mut budget = MAX_CHECK_BYTES;
        for path in self.copies() {
            let Some(stamp) = stamp(&path) else {
                continue;
            };
            if !all && self.seen.get(&path) == Some(&stamp) {
                continue;
            }
            if stamp.len > MAX_COPY_BYTES {
                out.push(Changed {
                    path,
                    bytes: Vec::new(),
                    stamp,
                    too_big: true,
                });
                continue;
            }
            if stamp.len > budget {
                break;
            }
            let Some(bytes) = read_capped(&path, MAX_COPY_BYTES.min(budget)) else {
                continue;
            };
            budget -= bytes.len() as u64;
            out.push(Changed {
                path,
                bytes,
                stamp,
                too_big: false,
            });
        }
        out
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

    #[test]
    fn caps_copy_count_and_size() {
        let dir = std::env::temp_dir().join(format!("vaultd-sync-caps-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let main = dir.join("vault.svault");
        let f = Folder::new(main.clone());
        fs::write(&main, b"main").unwrap();
        for i in 0..(MAX_OTHER_COPIES + 10) {
            fs::write(dir.join(format!("vault ({i:02}).svault")), b"x").unwrap();
        }
        // The synced copy plus at most MAX_OTHER_COPIES others.
        assert_eq!(f.copies().len(), 1 + MAX_OTHER_COPIES);
        assert_eq!(f.changed(true).len(), 1 + MAX_OTHER_COPIES);

        // An oversized copy is reported, not read (a sparse file, so the
        // test does not write 64 MiB).
        let big = fs::File::create(dir.join("vault (00).svault")).unwrap();
        big.set_len(MAX_COPY_BYTES + 1).unwrap();
        let c = f.changed(true);
        let big = c
            .iter()
            .find(|c| c.path.ends_with("vault (00).svault"))
            .unwrap();
        assert!(big.too_big && big.bytes.is_empty());
        assert!(c.iter().filter(|c| !c.too_big).all(|c| !c.bytes.is_empty()));

        // A file that grows past the cap after its length was read is cut off.
        let p = dir.join("grown");
        fs::write(&p, b"0123456789").unwrap();
        assert_eq!(read_capped(&p, 10).unwrap(), b"0123456789");
        assert_eq!(read_capped(&p, 9), None);
        fs::remove_dir_all(&dir).unwrap();
    }
}
