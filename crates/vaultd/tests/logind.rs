//! The logind watcher against a private D-Bus daemon that impersonates logind.
#![cfg(all(feature = "logind", target_os = "linux"))]

use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use vaultd::logind::{Event, watch};
use zbus::blocking::{Connection, connection};

#[test]
fn locks_on_sleep_and_session_lock_only() {
    let Ok(mut bus) = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address"])
        .stdout(Stdio::piped())
        .spawn()
    else {
        eprintln!("skipped: dbus-daemon is not installed");
        return;
    };
    let mut addr = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(bus.stdout.take().unwrap()),
        &mut addr,
    )
    .unwrap();
    let addr = addr.trim().to_owned();

    let logind = connection::Builder::address(addr.as_str())
        .unwrap()
        .name("org.freedesktop.login1")
        .unwrap()
        .build()
        .unwrap();
    let (tx, rx) = mpsc::channel();
    let watcher_addr = addr.clone();
    std::thread::spawn(move || {
        let conn = connection::Builder::address(watcher_addr.as_str())
            .unwrap()
            .build()
            .unwrap();
        tx.send(None).unwrap();
        let _ = watch(&conn, |e| tx.send(Some(e)).unwrap());
    });
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), None);
    std::thread::sleep(Duration::from_millis(300)); // let the match rule register

    let send_bool = |c: &Connection, iface: &str, member: &str| {
        c.emit_signal(
            None::<&str>,
            "/org/freedesktop/login1",
            iface,
            member,
            &(false,),
        )
        .unwrap();
        c.emit_signal(
            None::<&str>,
            "/org/freedesktop/login1",
            iface,
            member,
            &(true,),
        )
        .unwrap();
    };
    let send_empty = |c: &Connection, iface: &str, member: &str| {
        c.emit_signal(
            None::<&str>,
            "/org/freedesktop/login1/session/_31",
            iface,
            member,
            &(),
        )
        .unwrap();
    };
    send_bool(&logind, "org.freedesktop.login1.Manager", "PrepareForSleep");
    send_empty(&logind, "org.freedesktop.login1.Session", "Unlock");
    send_empty(&logind, "org.freedesktop.login1.Session", "Lock");

    // PrepareForSleep(false) (resume) and Unlock are ignored.
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(Event::Sleep)
    );
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(Event::SessionLock)
    );
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());

    // Someone else claiming to be logind is not believed.
    let impostor = connection::Builder::address(addr.as_str())
        .unwrap()
        .build()
        .unwrap();
    send_empty(&impostor, "org.freedesktop.login1.Session", "Lock");
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());

    let _ = bus.kill();
}
