//! `vaultw`: starts `vaultd` in the background on Windows, with no console
//! window, logging to `%LOCALAPPDATA%\vault\state\vaultd.log`. This is what
//! the installer runs at sign-in. Arguments are passed on to `vaultd`.
//!
//! vaultd still runs as the signed-in user, never elevated: its pipe and keys
//! belong to that user (docs/windows.md).

#![forbid(unsafe_code)]
// No console window of its own either.
#![cfg_attr(windows, windows_subsystem = "windows")]

/// The log is restarted past this size; the previous one is kept as `.old`.
#[cfg(windows)]
const MAX_LOG: u64 = 1 << 20;

#[cfg(windows)]
fn main() {
    use std::fs::{self, OpenOptions};
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    // CREATE_NO_WINDOW: vaultd gets a console (and so do the programs it
    // starts) but no window shows it.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let Ok(exe) = std::env::current_exe() else {
        std::process::exit(2)
    };
    let vaultd = exe.with_file_name("vaultd.exe");
    let dir = vault_ipc::local::state_dir();
    let _ = fs::create_dir_all(&dir);
    let log = dir.join("vaultd.log");
    if fs::metadata(&log).is_ok_and(|m| m.len() > MAX_LOG) {
        let _ = fs::rename(&log, dir.join("vaultd.log.old"));
    }
    let out = OpenOptions::new().create(true).append(true).open(&log);
    let (stdout, stderr) = match out.as_ref().map(|f| (f.try_clone(), f.try_clone())) {
        Ok((Ok(a), Ok(b))) => (Stdio::from(a), Stdio::from(b)),
        _ => (Stdio::null(), Stdio::null()),
    };
    let started = Command::new(&vaultd)
        .args(std::env::args_os().skip(1))
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
    if started.is_err() {
        std::process::exit(2)
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("vaultw is for Windows; elsewhere run vaultd from systemd (docs/vaultd.md)");
    std::process::exit(2)
}
