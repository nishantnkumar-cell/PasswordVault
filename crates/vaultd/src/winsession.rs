//! Windows: lock the vault when the session locks or the machine suspends,
//! the counterpart of `logind` on Linux. A hidden window receives the
//! session-change and power notifications.

#![allow(unsafe_code)]

use std::ptr::null_mut;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Power::RegisterSuspendResumeNotification;
use windows_sys::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DEVICE_NOTIFY_WINDOW_HANDLE, DefWindowProcW, DispatchMessageW, GetMessageW,
    MSG, PBT_APMSUSPEND, RegisterClassW, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WNDCLASSW,
    WS_OVERLAPPED,
};

use crate::server::Shared;

const WTS_SESSION_LOCK: usize = 0x7;

static DAEMON: OnceLock<Shared> = OnceLock::new();

/// What a notification means for the vault.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    SessionLock,
    Suspend,
}

/// Map a window message to an event, if it is one we lock on.
pub fn event(msg: u32, wparam: WPARAM) -> Option<Event> {
    match (msg, wparam) {
        (WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK) => Some(Event::SessionLock),
        (WM_POWERBROADCAST, w) if w == PBT_APMSUSPEND as usize => Some(Event::Suspend),
        _ => None,
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if let (Some(e), Some(d)) = (event(msg, wparam), DAEMON.get()) {
        eprintln!("vaultd: {e:?}, locking");
        d.lock().unwrap_or_else(|p| p.into_inner()).lock();
    }
    // SAFETY: forwarding the message we were given.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// Watch for session lock and suspend forever. Runs on its own thread.
pub fn run(daemon: Shared) {
    if DAEMON.set(daemon).is_err() {
        return;
    }
    let class: Vec<u16> = "vaultd-session\0".encode_utf16().collect();
    // SAFETY: plain Win32 window setup on this thread; every pointer passed
    // is valid for the call, and `class` outlives the window.
    unsafe {
        let instance = GetModuleHandleW(null_mut());
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: instance,
            lpszClassName: class.as_ptr(),
            ..std::mem::zeroed()
        };
        if RegisterClassW(&wc) == 0 {
            eprintln!(
                "vaultd: warning: cannot watch for screen lock: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        // A hidden top-level window: message-only windows miss power broadcasts.
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            class.as_ptr(),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            instance,
            null_mut(),
        );
        if hwnd.is_null() {
            eprintln!(
                "vaultd: warning: cannot watch for screen lock: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        if WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) == 0 {
            eprintln!(
                "vaultd: warning: cannot watch for screen lock: {}",
                std::io::Error::last_os_error()
            );
        }
        if RegisterSuspendResumeNotification(hwnd, DEVICE_NOTIFY_WINDOW_HANDLE) == 0 {
            eprintln!(
                "vaultd: warning: cannot watch for suspend: {}",
                std::io::Error::last_os_error()
            );
        }
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            DispatchMessageW(&msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_on_session_lock_and_suspend_only() {
        assert_eq!(event(WM_WTSSESSION_CHANGE, 0x7), Some(Event::SessionLock));
        assert_eq!(event(WM_WTSSESSION_CHANGE, 0x8), None); // unlock
        assert_eq!(
            event(WM_POWERBROADCAST, PBT_APMSUSPEND as usize),
            Some(Event::Suspend)
        );
        assert_eq!(event(WM_POWERBROADCAST, 0x12), None); // resume
    }
}
