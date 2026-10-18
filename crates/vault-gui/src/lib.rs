//! Desktop app for `vaultd`: the window and its connection to the daemon.

#![forbid(unsafe_code)]

pub mod app;
pub mod client;

pub use app::{App, Clip, Screen, SystemClip};
pub use client::Paths;
