//! macOS: lock the vault when the screen locks, the Mac is about to sleep,
//! or someone switches to another account (fast user switching), the
//! counterpart of `logind` on Linux and `winsession` on Windows.
//!
//! One thread runs a Core Foundation run loop with three sources:
//!
//! - the distributed notification `com.apple.screenIsLocked`, which
//!   loginwindow posts the moment the screen locks;
//! - IOKit's system power notifications, so the vault locks before sleep
//!   (the Mac waits for us to answer before it sleeps);
//! - a two-second check of this session's Quartz state, which catches a
//!   switch to another account and any screen lock the notification missed.
//!
//! Like the other platforms, any doubt locks: locking too often is safe,
//! missing a lock is not. Everything here needs the person's desktop
//! session, which the launch agent gives `vaultd`; a `vaultd` started over
//! SSH only gets the sleep notifications.

#![allow(unsafe_code)]

use std::ffi::{CStr, c_void};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use crate::server::Shared;

/// Why a lock was triggered.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Event {
    /// The screen locked (`com.apple.screenIsLocked`, or seen by the check).
    ScreenLock,
    /// The Mac is about to sleep.
    Sleep,
    /// This account is no longer the one on screen (fast user switching).
    SwitchedOut,
}

/// What the periodic check sees of this desktop session.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Session {
    /// This session owns the screen (`kCGSessionOnConsoleKey`).
    pub on_console: bool,
    /// The lock screen is up (`CGSSessionScreenIsLocked`).
    pub locked: bool,
}

/// What a change between two checks means. The first check (no `before`)
/// never locks: there is nothing to compare with yet.
pub fn session_event(before: Option<Session>, now: Session) -> Option<Event> {
    let before = before?;
    if before.on_console && !now.on_console {
        Some(Event::SwitchedOut)
    } else if !before.locked && now.locked {
        Some(Event::ScreenLock)
    } else {
        None
    }
}

/// `kIOMessageSystemWillSleep`: sleep is starting, answer before it does.
const SYSTEM_WILL_SLEEP: u32 = 0xE000_0280;
/// `kIOMessageCanSystemSleep`: idle sleep asks first; we never object.
const CAN_SYSTEM_SLEEP: u32 = 0xE000_0270;

/// Map an IOKit power message to an event, if it is one we lock on.
pub fn power_event(message: u32) -> Option<Event> {
    (message == SYSTEM_WILL_SLEEP).then_some(Event::Sleep)
}

/// Whether IOKit waits for an `IOAllowPowerChange` answer to `message`.
fn needs_answer(message: u32) -> bool {
    matches!(message, SYSTEM_WILL_SLEEP | CAN_SYSTEM_SLEEP)
}

/// The distributed notification loginwindow posts when the screen locks.
pub const SCREEN_LOCKED: &CStr = c"com.apple.screenIsLocked";

// ---- Core Foundation, Quartz and IOKit, the few calls this needs ----

type CFTypeRef = *const c_void;
type CFStringRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFRunLoopRef = *const c_void;
type CFRunLoopSourceRef = *const c_void;
type CFRunLoopTimerRef = *const c_void;
type CFNotificationCenterRef = *const c_void;
type IONotificationPortRef = *const c_void;
type CFIndex = isize;
type IoObject = u32;

#[repr(C)]
struct CFRunLoopTimerContext {
    version: CFIndex,
    info: *mut c_void,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
}

const UTF8: u32 = 0x0800_0100;
/// `CFNotificationSuspensionBehaviorDeliverImmediately`.
const DELIVER_IMMEDIATELY: CFIndex = 4;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFRunLoopDefaultMode: CFStringRef;
    fn CFStringCreateWithCString(alloc: CFTypeRef, s: *const i8, encoding: u32) -> CFStringRef;
    fn CFNotificationCenterGetDistributedCenter() -> CFNotificationCenterRef;
    fn CFNotificationCenterAddObserver(
        center: CFNotificationCenterRef,
        observer: *const c_void,
        callback: extern "C" fn(
            CFNotificationCenterRef,
            *mut c_void,
            CFStringRef,
            *const c_void,
            CFDictionaryRef,
        ),
        name: CFStringRef,
        object: *const c_void,
        suspension: CFIndex,
    );
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopAddSource(rl: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
    fn CFRunLoopAddTimer(rl: CFRunLoopRef, timer: CFRunLoopTimerRef, mode: CFStringRef);
    fn CFRunLoopRun();
    fn CFAbsoluteTimeGetCurrent() -> f64;
    fn CFRunLoopTimerCreate(
        alloc: CFTypeRef,
        fire: f64,
        interval: f64,
        flags: u64,
        order: CFIndex,
        callback: extern "C" fn(CFRunLoopTimerRef, *mut c_void),
        context: *mut CFRunLoopTimerContext,
    ) -> CFRunLoopTimerRef;
    fn CFDictionaryGetValue(dict: CFDictionaryRef, key: *const c_void) -> *const c_void;
    fn CFBooleanGetTypeID() -> usize;
    fn CFNumberGetTypeID() -> usize;
    fn CFGetTypeID(v: CFTypeRef) -> usize;
    fn CFBooleanGetValue(b: CFTypeRef) -> u8;
    fn CFNumberGetValue(n: CFTypeRef, kind: CFIndex, out: *mut c_void) -> u8;
    fn CFRelease(v: CFTypeRef);
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
}

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IORegisterForSystemPower(
        refcon: *mut c_void,
        port: *mut IONotificationPortRef,
        callback: extern "C" fn(*mut c_void, IoObject, u32, *mut c_void),
        notifier: *mut IoObject,
    ) -> IoObject;
    fn IONotificationPortGetRunLoopSource(port: IONotificationPortRef) -> CFRunLoopSourceRef;
    fn IOAllowPowerChange(root: IoObject, id: isize) -> i32;
}

static DAEMON: OnceLock<Shared> = OnceLock::new();
/// The power connection `IOAllowPowerChange` answers on.
static ROOT_PORT: AtomicU32 = AtomicU32::new(0);
/// The last check's session state: 0 none yet, else 1 | on_console<<1 | locked<<2.
static LAST: AtomicU8 = AtomicU8::new(0);

fn lock(e: Event) {
    if let Some(d) = DAEMON.get() {
        eprintln!("vaultd: {e:?}, locking");
        d.lock().unwrap_or_else(|p| p.into_inner()).lock();
    }
}

fn cfstr(s: &CStr) -> CFStringRef {
    // SAFETY: a valid NUL-terminated string; the result is kept for the
    // life of the process (never released), as the run loop needs it.
    unsafe { CFStringCreateWithCString(std::ptr::null(), s.as_ptr(), UTF8) }
}

/// True if `dict[key]` is a true boolean or a non-zero number.
///
/// # Safety
/// `dict` must be a valid CFDictionary.
unsafe fn flag(dict: CFDictionaryRef, key: &CStr) -> bool {
    let k = cfstr(key);
    // SAFETY: valid dictionary and key; the value is borrowed, not owned.
    unsafe {
        let v = CFDictionaryGetValue(dict, k);
        let out = if v.is_null() {
            false
        } else if CFGetTypeID(v) == CFBooleanGetTypeID() {
            CFBooleanGetValue(v) != 0
        } else if CFGetTypeID(v) == CFNumberGetTypeID() {
            let mut n: i64 = 0;
            // kCFNumberSInt64Type = 4
            CFNumberGetValue(v, 4, (&raw mut n).cast()) != 0 && n != 0
        } else {
            false
        };
        CFRelease(k);
        out
    }
}

/// This session as Quartz sees it, or `None` outside a desktop session.
fn current_session() -> Option<Session> {
    // SAFETY: the copy is ours to release; NULL means no window server.
    unsafe {
        let d = CGSessionCopyCurrentDictionary();
        if d.is_null() {
            return None;
        }
        let s = Session {
            on_console: flag(d, c"kCGSessionOnConsoleKey"),
            locked: flag(d, c"CGSSessionScreenIsLocked"),
        };
        CFRelease(d);
        Some(s)
    }
}

fn pack(s: Session) -> u8 {
    1 | (u8::from(s.on_console) << 1) | (u8::from(s.locked) << 2)
}

fn unpack(b: u8) -> Option<Session> {
    (b & 1 == 1).then_some(Session {
        on_console: b & 2 != 0,
        locked: b & 4 != 0,
    })
}

extern "C" fn on_screen_locked(
    _center: CFNotificationCenterRef,
    _observer: *mut c_void,
    _name: CFStringRef,
    _object: *const c_void,
    _info: CFDictionaryRef,
) {
    lock(Event::ScreenLock);
}

extern "C" fn on_timer(_timer: CFRunLoopTimerRef, _info: *mut c_void) {
    let Some(now) = current_session() else {
        return;
    };
    let before = unpack(LAST.swap(pack(now), Ordering::Relaxed));
    if let Some(e) = session_event(before, now) {
        lock(e);
    }
}

extern "C" fn on_power(_refcon: *mut c_void, _service: IoObject, message: u32, arg: *mut c_void) {
    if let Some(e) = power_event(message) {
        lock(e);
    }
    if needs_answer(message) {
        // SAFETY: answering IOKit on the connection it gave us, with the
        // notification id it passed in `arg`.
        unsafe { IOAllowPowerChange(ROOT_PORT.load(Ordering::Relaxed), arg as isize) };
    }
}

/// Watch for screen lock, sleep and account switches forever. Runs on its
/// own thread.
pub fn run(daemon: Shared) {
    if DAEMON.set(daemon).is_err() {
        return;
    }
    // SAFETY: plain Core Foundation and IOKit setup on this thread; the
    // run loop, sources and timer live until the process exits.
    unsafe {
        let rl = CFRunLoopGetCurrent();
        let mode = kCFRunLoopDefaultMode;

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDistributedCenter(),
            (&raw const DAEMON).cast(),
            on_screen_locked,
            cfstr(SCREEN_LOCKED),
            std::ptr::null(),
            DELIVER_IMMEDIATELY,
        );

        let mut port: IONotificationPortRef = std::ptr::null();
        let mut notifier: IoObject = 0;
        let root =
            IORegisterForSystemPower(std::ptr::null_mut(), &mut port, on_power, &mut notifier);
        if root == 0 || port.is_null() {
            eprintln!("vaultd: warning: cannot watch for sleep");
        } else {
            ROOT_PORT.store(root, Ordering::Relaxed);
            CFRunLoopAddSource(rl, IONotificationPortGetRunLoopSource(port), mode);
        }

        if current_session().is_none() {
            eprintln!(
                "vaultd: warning: not in a desktop session, will not lock on screen lock or account switch"
            );
        }
        let mut ctx = CFRunLoopTimerContext {
            version: 0,
            info: std::ptr::null_mut(),
            retain: std::ptr::null(),
            release: std::ptr::null(),
            copy_description: std::ptr::null(),
        };
        let timer = CFRunLoopTimerCreate(
            std::ptr::null(),
            CFAbsoluteTimeGetCurrent(),
            2.0,
            0,
            0,
            on_timer,
            &mut ctx,
        );
        CFRunLoopAddTimer(rl, timer, mode);

        CFRunLoopRun();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ON: Session = Session {
        on_console: true,
        locked: false,
    };

    #[test]
    fn first_check_never_locks() {
        let locked = Session {
            on_console: true,
            locked: true,
        };
        assert_eq!(session_event(None, locked), None);
        assert_eq!(session_event(None, ON), None);
    }

    #[test]
    fn locks_on_screen_lock_and_switch_out_only() {
        let locked = Session {
            on_console: true,
            locked: true,
        };
        let away = Session {
            on_console: false,
            locked: false,
        };
        assert_eq!(session_event(Some(ON), locked), Some(Event::ScreenLock));
        assert_eq!(session_event(Some(ON), away), Some(Event::SwitchedOut));
        assert_eq!(session_event(Some(locked), ON), None); // unlocked
        assert_eq!(session_event(Some(away), ON), None); // switched back
        assert_eq!(session_event(Some(locked), locked), None);
        assert_eq!(session_event(Some(ON), ON), None);
    }

    #[test]
    fn locks_before_sleep_only() {
        assert_eq!(power_event(SYSTEM_WILL_SLEEP), Some(Event::Sleep));
        assert_eq!(power_event(CAN_SYSTEM_SLEEP), None);
        assert_eq!(power_event(0xE000_0300), None); // has powered on
        assert!(needs_answer(CAN_SYSTEM_SLEEP) && needs_answer(SYSTEM_WILL_SLEEP));
        assert!(!needs_answer(0xE000_0300));
    }

    #[test]
    fn session_state_round_trips() {
        for on_console in [false, true] {
            for locked in [false, true] {
                let s = Session { on_console, locked };
                assert_eq!(unpack(pack(s)), Some(s));
            }
        }
        assert_eq!(unpack(0), None);
    }
}
