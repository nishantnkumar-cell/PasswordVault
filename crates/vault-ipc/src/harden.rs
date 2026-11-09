//! Windows process hardening for the programs that hold vault secrets:
//! keep them out of crash dumps, keep other programs from reading their
//! memory, and (for vaultd) keep heap pages out of the page file. The
//! Windows counterpart of vaultd's `harden()` on Linux and macOS
//! (docs/windows.md, "Memory protection").

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::c_void;
use std::io;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_KERNEL_OBJECT,
    SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
};
use windows_sys::Win32::System::ErrorReporting::WerAddExcludedApplication;
use windows_sys::Win32::System::Memory::{
    GetProcessWorkingSetSizeEx, QUOTA_LIMITS_HARDWS_MAX_DISABLE, QUOTA_LIMITS_HARDWS_MIN_DISABLE,
    SetProcessWorkingSetSizeEx, VirtualLock,
};
use windows_sys::Win32::System::SystemServices::{
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_0, PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY_0,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
    SetProcessMitigationPolicy,
};

/// What a process may do to us: wait on it, read its name and user, and end
/// it (the installer and Task Manager stop vaultd). No memory reads or
/// writes, no thread injection, no handle duplication.
/// SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE.
const OTHERS_MAY: u32 = 0x0010_0000 | 0x1000 | 0x0001;

/// Set `VAULT_HARDEN=off` to skip the process ACL and the mitigation
/// policies (for a debugger, or to rule them out when something breaks).
/// Crash dump exclusion and memory locking stay on.
fn hardening_off() -> bool {
    std::env::var_os("VAULT_HARDEN").is_some_and(|v| v == "off")
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// The steps every secret-holding program takes: no crash dumps and no
/// memory reads from other processes. Returns warnings for the log; none of
/// these failures stops the program.
pub fn harden_process() -> Vec<String> {
    let mut warn = Vec::new();
    // No "stopped working" box and no Windows Error Reporting dump of this
    // program for this user. (A full kernel crash dump still holds all of
    // RAM; BitLocker protects that file and the page file.)
    // SAFETY: plain flag call.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)
    };
    if let Some(name) = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
    {
        let w = wide(&name);
        // SAFETY: `w` is a NUL-terminated UTF-16 string that outlives the call.
        let hr = unsafe { WerAddExcludedApplication(w.as_ptr(), 0) };
        if hr < 0 {
            warn.push(format!(
                "could not exclude {name} from Windows Error Reporting (0x{hr:08x}); a crash may save a dump"
            ));
        }
    }
    if hardening_off() {
        warn.push(
            "VAULT_HARDEN=off: other programs of this user can read this process's memory".into(),
        );
    } else if let Err(e) = restrict_process_acl() {
        warn.push(format!("could not restrict access to this process: {e}"));
    }
    warn
}

/// Extra steps for vaultd, which has no text input or other UI that needs
/// system extension points: no legacy DLL injection (AppInit DLLs, global
/// window hooks), and system DLLs load only from System32, never from the
/// program's folder or a network share.
pub fn harden_daemon() -> Vec<String> {
    let mut warn = harden_process();
    if hardening_off() {
        return warn;
    }
    // Bit 0 of each policy's flags: DisableExtensionPoints.
    let ext = PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY {
        Anonymous: PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_0 { Flags: 1 },
    };
    // SAFETY: `ext` is the policy struct the call expects, of that size.
    let ok = unsafe {
        SetProcessMitigationPolicy(
            ProcessExtensionPointDisablePolicy,
            (&ext as *const PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY).cast(),
            size_of::<PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY>(),
        )
    };
    if ok == 0 {
        warn.push(format!(
            "could not turn off DLL extension points: {}",
            io::Error::last_os_error()
        ));
    }
    // NoRemoteImages (bit 0) | PreferSystem32Images (bit 2).
    let img = PROCESS_MITIGATION_IMAGE_LOAD_POLICY {
        Anonymous: PROCESS_MITIGATION_IMAGE_LOAD_POLICY_0 { Flags: 0b101 },
    };
    // SAFETY: as above.
    let ok = unsafe {
        SetProcessMitigationPolicy(
            ProcessImageLoadPolicy,
            (&img as *const PROCESS_MITIGATION_IMAGE_LOAD_POLICY).cast(),
            size_of::<PROCESS_MITIGATION_IMAGE_LOAD_POLICY>(),
        )
    };
    if ok == 0 {
        warn.push(format!(
            "could not set the DLL load policy: {}",
            io::Error::last_os_error()
        ));
    }
    warn
}

/// Replace this process's ACL: our user may only wait on, query and end
/// it; SYSTEM keeps full access. The owner can still change the ACL back,
/// and an administrator with the debug privilege ignores it, so this stops
/// casual memory readers running as us, not a determined one (threat
/// model A3: same-user malware is out of scope; this raises its cost).
fn restrict_process_acl() -> io::Result<()> {
    let sid = crate::win::sid_string(&crate::win::current_user()?)?;
    let sddl = wide(&format!("D:P(A;;0x{OTHERS_MAY:x};;;{sid})(A;;GA;;;SY)"));
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `sddl` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = null_mut();
        // SAFETY: `sd` is the valid descriptor made above.
        if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the pseudo-handle has WRITE_DAC on our own process; `dacl`
        // points into `sd`, alive until LocalFree below.
        let rc = unsafe {
            SetSecurityInfo(
                GetCurrentProcess(),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        Ok(())
    })();
    // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe { LocalFree(sd as HLOCAL) };
    result
}

/// Keep a window out of screenshots, screen recording and screen sharing
/// (`WDA_EXCLUDEFROMCAPTURE`, Windows 10 2004 or later; older builds show
/// it black instead, `WDA_MONITOR`). Set `VAULT_ALLOW_CAPTURE=1` to allow
/// capture. Returns whether the window is now protected.
pub fn exclude_from_capture(hwnd: isize) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR,
    };
    if capture_allowed() {
        return false;
    }
    let hwnd = hwnd as windows_sys::Win32::Foundation::HWND;
    // SAFETY: `hwnd` is a live top-level window of this process (the
    // caller's own); the call only changes how it is composited.
    unsafe {
        SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) != 0
            || SetWindowDisplayAffinity(hwnd, WDA_MONITOR) != 0
    }
}

/// Whether `VAULT_ALLOW_CAPTURE=1` lets screenshots include the app.
pub fn capture_allowed() -> bool {
    std::env::var_os("VAULT_ALLOW_CAPTURE").is_some_and(|v| v == "1")
}

/// How many allocations could not be locked in RAM since the start.
static NOT_LOCKED: AtomicUsize = AtomicUsize::new(0);

/// The most the locked working set may grow to: past this, the vault's own
/// Argon2id ceiling (4 GiB) plus room for everything else.
const MAX_LOCKED: usize = 5 << 30;

/// A global allocator that locks every block it hands out into RAM with
/// `VirtualLock`, so keys, decrypted items and Argon2id buffers never reach
/// the page file. Windows has no `mlockall`; this is the closest match.
///
/// Locking a page is idempotent and pages are shared between blocks, so
/// nothing is unlocked on free: the heap returns large blocks to the system
/// (which drops their lock) and reuses small ones (which stay locked).
/// When the working set quota is full the minimum working set is raised to
/// fit and the lock retried. The allocator never allocates itself.
pub struct LockedAlloc;

/// Allocations that could not be locked so far (0 is the goal).
pub fn unlocked_allocations() -> usize {
    NOT_LOCKED.load(Ordering::Relaxed)
}

fn lock(p: *mut u8, len: usize) {
    // SAFETY: `p..p+len` was just allocated and is committed memory.
    if len == 0 || unsafe { VirtualLock(p as *const c_void, len) } != 0 {
        return;
    }
    if grow_working_set(len) && unsafe { VirtualLock(p as *const c_void, len) } != 0 {
        return;
    }
    NOT_LOCKED.fetch_add(1, Ordering::Relaxed);
}

/// Raise the minimum working set by `len` plus slack. Races between
/// threads only raise it a little more than needed.
fn grow_working_set(len: usize) -> bool {
    const SLACK: usize = 4 << 20;
    let (mut min, mut max, mut flags) = (0usize, 0usize, 0u32);
    // SAFETY: out-pointers to locals; the pseudo-handle needs no closing.
    let me = unsafe { GetCurrentProcess() };
    if unsafe { GetProcessWorkingSetSizeEx(me, &mut min, &mut max, &mut flags) } == 0 {
        return false;
    }
    let new_min = min
        .saturating_add(len.next_multiple_of(1 << 20))
        .saturating_add(SLACK);
    if new_min > MAX_LOCKED {
        return false;
    }
    let new_max = max.max(new_min.saturating_add(64 << 20));
    // SAFETY: plain call on our own process. Users hold the "increase a
    // process working set" privilege by default.
    unsafe {
        SetProcessWorkingSetSizeEx(
            me,
            new_min,
            new_max,
            QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE,
        ) != 0
    }
}

// SAFETY: every call goes straight to `System`; `lock` only touches page
// protection state and never allocates.
unsafe impl GlobalAlloc for LockedAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, passed on.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            lock(p, layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as above.
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            lock(p, layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as above.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: as above.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            lock(p, new_size);
        }
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_small_and_large_blocks() {
        let before = unlocked_allocations();
        let a = LockedAlloc;
        for size in [32, 4096, 3 << 20, 64 << 20] {
            let layout = Layout::from_size_align(size, 16).unwrap();
            // SAFETY: non-zero size; freed with the same layout.
            unsafe {
                let p = a.alloc_zeroed(layout);
                assert!(!p.is_null());
                *p.add(size - 1) = 1;
                a.dealloc(p, layout);
            }
        }
        assert_eq!(
            unlocked_allocations(),
            before,
            "an allocation was not locked"
        );
    }
}
