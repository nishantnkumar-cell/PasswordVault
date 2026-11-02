//! Files the calling program hands over by number, as GPGME does: the
//! `--status-fd N` channel and, with `--enable-special-filenames`, file
//! names of the form `-&N`. On Unix N is a file descriptor; on Windows it
//! is the value of an inherited handle, as with gpg itself.

use std::fs::File;
use std::io;

/// `-&N` as a file name: N, if special file names are on.
pub fn special(name: &str, enabled: bool) -> Option<i64> {
    let n = name.strip_prefix("-&").filter(|_| enabled)?;
    n.parse().ok().filter(|n| *n >= 0)
}

/// The descriptor (Unix) or handle (Windows) `n` that the caller left open
/// for this process.
#[cfg(unix)]
pub fn open(n: i64, write: bool) -> io::Result<File> {
    // /dev/fd/N opens the caller's pipe again, on Linux and macOS, with no
    // unsafe code.
    let path = format!("/dev/fd/{n}");
    if write {
        std::fs::OpenOptions::new().append(true).open(path)
    } else {
        File::open(path)
    }
}

/// The descriptor (Unix) or handle (Windows) `n` that the caller left open
/// for this process.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn open(n: i64, _write: bool) -> io::Result<File> {
    use std::os::windows::io::{AsHandle, FromRawHandle, RawHandle};
    // As in gpg, 0, 1 and 2 are the standard streams, not handle values.
    let std = match n {
        0 => Some(io::stdin().as_handle().try_clone_to_owned()),
        1 => Some(io::stdout().as_handle().try_clone_to_owned()),
        2 => Some(io::stderr().as_handle().try_clone_to_owned()),
        _ => None,
    };
    if let Some(h) = std {
        return h.map(File::from);
    }
    if n < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{n} is not a handle"),
        ));
    }
    // SAFETY: GPGME passes the value of an inheritable pipe handle it
    // created for this process and does not use our copy; each number is
    // taken over once, so the handle has exactly one owner. A wrong number
    // makes reads and writes fail with "invalid handle".
    Ok(unsafe { File::from_raw_handle(n as usize as RawHandle) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_names() {
        assert_eq!(special("-&7", true), Some(7));
        assert_eq!(special("-&7", false), None);
        assert_eq!(special("-&x", true), None);
        assert_eq!(special("-&-1", true), None);
        assert_eq!(special("-", true), None);
        assert_eq!(special("mail.eml", true), None);
    }
}
