//! Windows: which user a process runs as, so each end of the named pipe can
//! check the other. The only unsafe code in the crate.

#![allow(unsafe_code)]

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

fn check(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// The SID, as bytes, of the user `process` runs as.
fn token_user(process: HANDLE) -> io::Result<Vec<u8>> {
    let mut token: HANDLE = null_mut();
    // SAFETY: `process` is a valid process handle; `token` receives a new handle.
    check(unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) })?;
    // SAFETY: OpenProcessToken succeeded, so `token` is ours to close.
    let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
    let h = token.as_raw_handle() as HANDLE;
    let mut len = 0u32;
    // SAFETY: a size query with a null buffer; it fails and sets `len`.
    unsafe { GetTokenInformation(h, TokenUser, null_mut(), 0, &mut len) };
    // u64 elements keep the buffer aligned for TOKEN_USER.
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` holds at least `len` bytes.
    check(unsafe { GetTokenInformation(h, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) })?;
    // SAFETY: the call filled `buf` with a TOKEN_USER whose SID points into `buf`.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: `sid` is a valid SID inside `buf`, which outlives this read.
    let n = unsafe { GetLengthSid(sid) } as usize;
    Ok(unsafe { std::slice::from_raw_parts(sid as *const u8, n) }.to_vec())
}

/// The SID of the user running this process.
pub fn current_user() -> io::Result<Vec<u8>> {
    // SAFETY: the pseudo-handle needs no closing.
    token_user(unsafe { GetCurrentProcess() })
}

/// The SID of the user running process `pid`.
pub fn process_user(pid: u32) -> io::Result<Vec<u8>> {
    // SAFETY: returns a new handle or null.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcess succeeded, so the handle is ours to close.
    let h = unsafe { OwnedHandle::from_raw_handle(h as RawHandle) };
    token_user(h.as_raw_handle() as HANDLE)
}

/// A SID in its `S-1-5-21-…` text form.
pub fn sid_string(sid: &[u8]) -> io::Result<String> {
    let mut out: *mut u16 = null_mut();
    // SAFETY: `sid` holds a SID read from a token; `out` receives a LocalAlloc'd string.
    check(unsafe { ConvertSidToStringSidW(sid.as_ptr() as *mut _, &mut out) })?;
    // SAFETY: `out` is NUL-terminated.
    let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
    let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) });
    // SAFETY: allocated by ConvertSidToStringSidW.
    unsafe { LocalFree(out.cast()) };
    Ok(s)
}

/// Process ID of the server end of a named pipe client handle.
pub fn pipe_server_pid(pipe: &impl AsRawHandle) -> io::Result<u32> {
    let mut pid = 0;
    // SAFETY: `pipe` is an open pipe handle.
    check(unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) })?;
    Ok(pid)
}

/// Process ID of the client end of a named pipe server handle.
pub fn pipe_client_pid(pipe: &impl AsRawHandle) -> io::Result<u32> {
    let mut pid = 0;
    // SAFETY: `pipe` is an open, connected pipe handle.
    check(unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) })?;
    Ok(pid)
}

/// Full path of process `pid`'s executable.
pub fn process_path(pid: u32) -> io::Result<String> {
    use windows_sys::Win32::System::Threading::{PROCESS_NAME_WIN32, QueryFullProcessImageNameW};
    // SAFETY: returns a new handle or null.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcess succeeded, so the handle is ours to close.
    let h = unsafe { OwnedHandle::from_raw_handle(h as RawHandle) };
    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` UTF-16 units.
    check(unsafe {
        QueryFullProcessImageNameW(
            h.as_raw_handle() as HANDLE,
            PROCESS_NAME_WIN32,
            buf.as_mut_ptr(),
            &mut len,
        )
    })?;
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}
