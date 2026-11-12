//! The macOS clipboard for secrets: copied text stays on this Mac.
//!
//! A normal copy on a Mac also goes to the person's iPhone, iPad and other
//! Macs through Universal Clipboard (Handoff). For a password that is a leak
//! the person did not ask for, so secrets are written with
//! `NSPasteboardContentsCurrentHostOnly`, which keeps them off Universal
//! Clipboard, and with `org.nspasteboard.ConcealedType`, which tells
//! clipboard history apps to skip them (<http://nspasteboard.org>).
//!
//! Not exercised by automated tests: needs a Mac's window server.

#![allow(unsafe_code)]

use objc2_app_kit::{NSPasteboard, NSPasteboardContentsOptions, NSPasteboardTypeString};
use objc2_foundation::NSString;

/// The marker type clipboard managers look for.
const CONCEALED: &str = "org.nspasteboard.ConcealedType";

/// Put `text` on the general pasteboard for this Mac only, hidden from
/// clipboard history.
pub fn set_secret(text: &str) -> Result<(), String> {
    let pb = NSPasteboard::generalPasteboard();
    // Clears the pasteboard and marks what follows as this-Mac-only.
    pb.prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly);
    // SAFETY: an AppKit constant, valid for the life of the process.
    let string_type = unsafe { NSPasteboardTypeString };
    if !pb.setString_forType(&NSString::from_str(text), string_type) {
        return Err("macOS did not accept the copy".into());
    }
    pb.setString_forType(&NSString::from_str(""), &NSString::from_str(CONCEALED));
    Ok(())
}
