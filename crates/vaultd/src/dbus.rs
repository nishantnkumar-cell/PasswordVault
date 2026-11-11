//! A small blocking layer over zbus 6, which has only an async API.
//!
//! vaultd's D-Bus code (the logind watch and the Secret Service) is plain
//! threads, not async tasks, so this wraps the few zbus calls it makes in
//! [`zbus::block_on`]. zbus is built with `tokio-multithread`, so its own
//! worker threads keep every connection moving (reading, writing, matching
//! signals) whether or not a thread is blocked here, as zbus 5's blocking
//! API did. Any thread may call these, as long as it is not a Tokio task.

use std::future::poll_fn;
use std::num::NonZeroUsize;
use std::pin::Pin;

use zbus::fdo::{RequestNameFlags, RequestNameReply};
use zbus::message::Header;
use zbus::names::{BusName, ErrorName, OwnedUniqueName, WellKnownName};
use zbus::wire::DynamicDeserialize;
use zbus::{DynamicType, MessageStream, OwnedMatchRule};
pub use zbus::{Error, MatchRule, Message, Result, block_on};

/// A bus connection. Cheap to clone; clones share the connection.
#[derive(Clone, Debug)]
pub struct Connection(zbus::Connection);

impl Connection {
    /// The session bus.
    pub fn session() -> Result<Self> {
        block_on(zbus::Connection::session()).map(Self)
    }

    /// The system bus.
    pub fn system() -> Result<Self> {
        block_on(zbus::Connection::system()).map(Self)
    }

    /// A bus at a D-Bus address, such as a test's own `dbus-daemon`.
    pub fn at(address: &str) -> Result<Self> {
        block_on(zbus::connection::Builder::address(address).build()).map(Self)
    }

    /// A bus at `address`, owning the well-known name `name` from the start.
    pub fn at_named(address: &str, name: &str) -> Result<Self> {
        block_on(
            zbus::connection::Builder::address(address)
                .name(name)
                .build(),
        )
        .map(Self)
    }

    /// The zbus connection underneath.
    pub fn inner(&self) -> &zbus::Connection {
        &self.0
    }

    /// This connection's unique name on the bus.
    pub fn unique_name(&self) -> Option<&OwnedUniqueName> {
        self.0.unique_name()
    }

    /// Reply to the method call `call` with `body`.
    pub fn reply<B>(&self, call: &Header<'_>, body: &B) -> Result<()>
    where
        B: serde::Serialize + DynamicType,
    {
        block_on(self.0.reply(call, body))
    }

    /// Reply the error `name` to the method call `call`.
    pub fn reply_error<'e, E, B>(&self, call: &Header<'_>, name: E, body: &B) -> Result<()>
    where
        B: serde::Serialize + DynamicType,
        E: TryInto<ErrorName<'e>>,
        E::Error: Into<Error>,
    {
        block_on(self.0.reply_error(call, name, body))
    }

    /// Ask the bus for the well-known name `name`.
    pub fn request_name_with_flags<'w, W>(
        &self,
        name: W,
        flags: RequestNameFlags,
    ) -> Result<RequestNameReply>
    where
        W: TryInto<WellKnownName<'w>>,
        W::Error: Into<Error>,
    {
        block_on(self.0.request_name_with_flags(name, flags))
    }

    /// Send a signal from `path`, to `dest` or to everyone listening.
    pub fn emit_signal<B>(
        &self,
        dest: Option<&str>,
        path: &str,
        iface: &str,
        member: &str,
        body: &B,
    ) -> Result<()>
    where
        B: serde::Serialize + DynamicType,
    {
        block_on(self.0.emit_signal(dest, path, iface, member, body))
    }
}

/// Messages arriving on a connection, as a blocking iterator.
pub struct MessageIterator(MessageStream);

impl MessageIterator {
    /// Every message the connection receives from now on.
    pub fn from(conn: &Connection) -> Self {
        Self(MessageStream::from(&conn.0))
    }

    /// The messages that match `rule`. The rule is added to the bus, and
    /// removed again when the iterator is dropped.
    pub fn for_match_rule<R>(
        rule: R,
        conn: &Connection,
        max_queued: Option<NonZeroUsize>,
    ) -> Result<Self>
    where
        R: TryInto<OwnedMatchRule>,
        R::Error: Into<Error>,
    {
        block_on(MessageStream::for_match_rule(rule, &conn.0, max_queued)).map(Self)
    }
}

impl Iterator for MessageIterator {
    type Item = Result<Message>;

    fn next(&mut self) -> Option<Self::Item> {
        use zbus::export::futures_core::Stream;
        let stream = &mut self.0;
        block_on(poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)))
    }
}

/// A remote object's interface.
pub struct Proxy<'a>(zbus::Proxy<'a>);

impl<'a> Proxy<'a> {
    /// The interface `iface` of the object `path` owned by `dest`.
    pub fn new(conn: &Connection, dest: &'a str, path: &'a str, iface: &'a str) -> Result<Self> {
        block_on(zbus::Proxy::new(&conn.0, dest, path, iface)).map(Self)
    }

    /// Call `method` with `body` and return the reply's body.
    pub fn call<B, R>(&self, method: &str, body: &B) -> Result<R>
    where
        B: serde::Serialize + DynamicType,
        R: for<'d> DynamicDeserialize<'d>,
    {
        block_on(self.0.call(method, body))
    }
}

/// The bus itself (`org.freedesktop.DBus`).
pub struct DBusProxy(zbus::fdo::DBusProxy<'static>);

impl DBusProxy {
    pub fn new(conn: &Connection) -> Result<Self> {
        block_on(zbus::fdo::DBusProxy::new(&conn.0)).map(Self)
    }

    pub fn add_match_rule(&self, rule: MatchRule<'_>) -> Result<()> {
        block_on(self.0.add_match_rule(rule)).map_err(Into::into)
    }

    pub fn name_has_owner(&self, name: BusName<'_>) -> Result<bool> {
        block_on(self.0.name_has_owner(name)).map_err(Into::into)
    }

    pub fn get_name_owner(&self, name: BusName<'_>) -> Result<OwnedUniqueName> {
        block_on(self.0.get_name_owner(name)).map_err(Into::into)
    }

    pub fn get_connection_unix_process_id(&self, name: BusName<'_>) -> Result<u32> {
        block_on(self.0.get_connection_unix_process_id(name)).map_err(Into::into)
    }

    pub fn get_connection_unix_user(&self, name: BusName<'_>) -> Result<u32> {
        block_on(self.0.get_connection_unix_user(name)).map_err(Into::into)
    }
}
