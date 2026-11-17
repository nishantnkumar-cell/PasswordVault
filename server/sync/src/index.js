// @ts-check
// Secret Vault cloud sync server (docs/cloud-sync.md): a Cloudflare Worker that
// keeps one encrypted vault file per mailbox, in a Durable Object. The vault
// program uploads this file to the user's own Cloudflare account
// (`vault cloud setup`), so it is plain JavaScript with no build step: the
// Rust crate vault-cloud embeds it as it is.
//
// The server never sees a key. It keeps the file the client uploads, a
// version number, and per-device access tokens (only their SHA-256). Merging,
// the header MAC and the refusal of old or retired copies all happen in the
// client (docs/format.md 5.1).
//
// API. Tokens are base64url, 256 bits. "Authorization: Bearer <token>" is a
// device token unless said otherwise.
//   GET    /                          {"service":"secret-vault-sync","api":1,"revision":N}
//   POST   /v1/m/<id>                 create an empty mailbox; X-Admin-Key; the
//                                     bearer token becomes the first device's
//   GET    /v1/m/<id>                 the file with ETag "<version>"; 204 while
//                                     empty (version 0); If-None-Match -> 304
//   PUT    /v1/m/<id>                 replace; If-Match "<version>" required (428);
//                                     412 with the current ETag if someone saved first
//   DELETE /v1/m/<id>                 delete the mailbox, its file and devices
//   POST   /v1/m/<id>/tickets         a one-time join ticket, valid 10 minutes
//   POST   /v1/m/<id>/join            X-Ticket; the bearer token is the new
//                                     device's, chosen by it; X-Device-Name
//   GET    /v1/m/<id>/devices         [{id,name,created,lastSeen,current}]
//   DELETE /v1/m/<id>/devices/<dev>   remove a device (a lost phone)
//   GET    /v1/m/<id>/watch           WebSocket: {"version":n} on connect and
//                                     after every save; "ping" -> "pong"
//   GET    /join                      a page telling a person who opened a join
//                                     link in a browser what to do with it

import { DurableObject } from "cloudflare:workers";

// Only the default handler and Mailbox may be exported: the Workers runtime
// refuses a main module that exports anything else. The tests repeat the
// limits below.

/** Bumped whenever this file changes, so `vault cloud status` can tell that
 * the deployed server is older than the program's copy. */
const REVISION = 1;

/** Largest vault file accepted. Vaults with thousands of items are < 1 MiB. */
const MAX_FILE = 4 * 1024 * 1024;
/** SQLite rows in a Durable Object are limited to 2 MB. */
const CHUNK = 1024 * 1024;
/** Saves per mailbox per minute before 429. */
const MAX_WRITES_PER_MINUTE = 60;
/** Open watch sockets per mailbox. */
const MAX_WATCHERS = 32;
/** Devices per mailbox. */
const MAX_DEVICES = 32;
/** Unused join tickets kept per mailbox. */
const MAX_TICKETS = 5;
const TICKET_SECONDS = 10 * 60;
/** last_seen is written at most this often per device (writes cost quota). */
const SEEN_EVERY_MS = 60 * 60 * 1000;

const ID_RE = /^[0-9a-f]{32}$/;
const DEVICE_RE = /^[0-9a-f]{16}$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{43,128}$/;

/**
 * @typedef {object} Env
 * @property {DurableObjectNamespace} MAILBOX
 * @property {string} [ADMIN_KEY] needed to create a mailbox; set by `vault cloud setup`
 */

const enc = new TextEncoder();

/** @param {string} s */
async function sha256hex(s) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** Compares two secrets without leaking where they differ.
 * @param {string} a @param {string} b */
async function sameSecret(a, b) {
  const [x, y] = await Promise.all([sha256hex(a), sha256hex(b)]);
  return crypto.subtle.timingSafeEqual(enc.encode(x), enc.encode(y));
}

/** @param {number} n */
function randomHex(n) {
  return [...crypto.getRandomValues(new Uint8Array(n))].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function randomToken() {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** @param {number} status @param {string} body @param {Record<string, string>} [headers] */
function text(status, body, headers = {}) {
  return new Response(body + "\n", {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}

/** @param {unknown} value @param {number} [status] */
function json(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

/** @param {number} version */
const etag = (version) => `"${version}"`;

/** "12", "\"12\"" or W/"12" -> 12; anything else -> null.
 * @param {string | null} h */
function parseTag(h) {
  if (h === null) return null;
  const m = h.trim().match(/^(?:W\/)?"?(\d{1,15})"?$/);
  return m ? Number(m[1]) : null;
}

/** @param {Request} req */
function bearer(req) {
  const m = (req.headers.get("authorization") ?? "").match(/^Bearer ([A-Za-z0-9_-]+)$/);
  return m && TOKEN_RE.test(m[1]) ? m[1] : null;
}

/** @param {string | null} name */
function deviceName(name) {
  return (name ?? "").replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 64) || "device";
}

const JOIN_PAGE = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Join a Secret Vault</title>
<body style="font:16px/1.5 system-ui,sans-serif;max-width:36em;margin:2em auto;padding:0 1em">
<h1>Join a Secret Vault</h1>
<p>This link adds a device to a vault's cloud sync. Open it with Secret Vault instead of a browser:</p>
<ul><li>Desktop app: <b>Sync</b> &rarr; <b>Join with a link</b>, and paste it.</li>
<li>Command line: <code>vault cloud join '&lt;the link&gt;'</code></li></ul>
<p>The link works once and for ten minutes. It holds no password or key: you still unlock with your master password.</p>
</body>`;

export default {
  /** @param {Request} req @param {Env} env */
  async fetch(req, env) {
    const url = new URL(req.url);
    // Plain http only on this computer, for `wrangler dev` and tests.
    const loopback = url.hostname === "127.0.0.1" || url.hostname === "localhost";
    if (url.protocol !== "https:" && !loopback) return text(400, "use https");
    if (url.pathname === "/" || url.pathname === "/v1") {
      return json({ service: "secret-vault-sync", api: 1, revision: REVISION });
    }
    if (url.pathname === "/join") {
      return new Response(JOIN_PAGE, { headers: { "content-type": "text/html; charset=utf-8" } });
    }
    const m = url.pathname.match(/^\/v1\/m\/([^/]+)(?:\/(tickets|join|devices|watch)(?:\/([^/]+))?)?$/);
    if (!m) return text(404, "not found");
    if (!ID_RE.test(m[1])) return text(400, "mailbox id must be 32 lowercase hex characters");
    if (req.method === "POST" && m[2] === undefined) {
      if (!env.ADMIN_KEY) return text(403, "this server has no admin key; run `vault cloud setup` again");
      if (!(await sameSecret(req.headers.get("x-admin-key") ?? "", env.ADMIN_KEY))) {
        return text(403, "wrong admin key");
      }
    }
    if (bearer(req) === null) return text(401, "missing or malformed token");
    const stub = env.MAILBOX.get(env.MAILBOX.idFromName(m[1]));
    return stub.fetch(req);
  },
};

/** One vault's mailbox. Requests to one Durable Object run one at a time, so
 * the version check and the write below cannot interleave with another. */
export class Mailbox extends DurableObject {
  /** @param {DurableObjectState} ctx @param {Env} env */
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    /** @type {number[]} */
    this.writes = [];
    this.schema();
    // Pings are answered without waking the object (no duration charge).
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  schema() {
    this.sql.exec("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)");
    this.sql.exec("CREATE TABLE IF NOT EXISTS chunks (i INTEGER PRIMARY KEY, data BLOB NOT NULL)");
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, name TEXT NOT NULL, token TEXT NOT NULL UNIQUE, created INTEGER NOT NULL, seen INTEGER NOT NULL)",
    );
    this.sql.exec("CREATE TABLE IF NOT EXISTS tickets (hash TEXT PRIMARY KEY, expires INTEGER NOT NULL)");
  }

  /** @param {string} k */
  meta(k) {
    const rows = this.sql.exec("SELECT v FROM meta WHERE k = ?", k).toArray();
    return rows.length ? String(rows[0].v) : null;
  }

  /** @param {string} k @param {string} v */
  setMeta(k, v) {
    this.sql.exec("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", k, v);
  }

  version() {
    return Number(this.meta("version") ?? "0");
  }

  /** @param {ArrayBuffer} file @param {number} version */
  store(file, version) {
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM chunks");
      for (let off = 0, i = 0; off < file.byteLength; off += CHUNK, i++) {
        this.sql.exec("INSERT INTO chunks (i, data) VALUES (?, ?)", i, file.slice(off, off + CHUNK));
      }
      this.setMeta("version", String(version));
    });
  }

  load() {
    const parts = this.sql
      .exec("SELECT data FROM chunks ORDER BY i")
      .toArray()
      .map((r) => new Uint8Array(/** @type {ArrayBuffer} */ (r.data)));
    const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
    let off = 0;
    for (const p of parts) {
      out.set(p, off);
      off += p.byteLength;
    }
    return out;
  }

  /** @param {Request} req @returns {Promise<ArrayBuffer | Response>} */
  async readBody(req) {
    const declared = Number(req.headers.get("content-length") ?? "0");
    if (declared > MAX_FILE) return text(413, `file larger than ${MAX_FILE} bytes`);
    const body = await req.arrayBuffer();
    if (body.byteLength > MAX_FILE) return text(413, `file larger than ${MAX_FILE} bytes`);
    if (body.byteLength === 0) return text(400, "empty file");
    return body;
  }

  /** Sliding one-minute window, kept in memory: a soft limit against a
   * runaway client, not a security boundary. */
  rateLimited() {
    const now = Date.now();
    this.writes = this.writes.filter((t) => now - t < 60_000);
    if (this.writes.length >= MAX_WRITES_PER_MINUTE) return true;
    this.writes.push(now);
    return false;
  }

  /** @param {number} version */
  notify(version) {
    const msg = JSON.stringify({ version });
    for (const ws of this.ctx.getWebSockets()) {
      try {
        ws.send(msg);
      } catch {
        // A socket that is closing; the client reconnects and asks again.
      }
    }
  }

  /** @param {string} id @param {string} name @param {string} tokenHash */
  addDevice(id, name, tokenHash) {
    const now = Date.now();
    this.sql.exec(
      "INSERT INTO devices (id, name, token, created, seen) VALUES (?, ?, ?, ?, ?)",
      id,
      name,
      tokenHash,
      now,
      now,
    );
  }

  /** The device a token belongs to, or null.
   * @param {string} token */
  async device(token) {
    const hash = await sha256hex(token);
    const rows = this.sql.exec("SELECT id, seen FROM devices WHERE token = ?", hash).toArray();
    if (!rows.length) return null;
    const id = String(rows[0].id);
    if (Date.now() - Number(rows[0].seen) > SEEN_EVERY_MS) {
      this.sql.exec("UPDATE devices SET seen = ? WHERE id = ?", Date.now(), id);
    }
    return id;
  }

  /** @param {Request} req */
  async fetch(req) {
    const url = new URL(req.url);
    const [, , , , sub = "", arg] = url.pathname.split("/");
    const token = /** @type {string} */ (bearer(req));
    const exists = this.meta("version") !== null;

    if (req.method === "POST" && sub === "") {
      if (exists) return text(409, "mailbox already exists");
      const id = randomHex(8);
      this.ctx.storage.transactionSync(() => {
        this.setMeta("version", "0");
        this.setMeta("created", String(Date.now()));
      });
      this.addDevice(id, deviceName(req.headers.get("x-device-name")), await sha256hex(token));
      return json({ device: id }, 201);
    }
    if (!exists) return text(401, "unknown mailbox or wrong token");

    if (req.method === "POST" && sub === "join") {
      const ticket = req.headers.get("x-ticket") ?? "";
      if (!TOKEN_RE.test(ticket)) return text(400, "X-Ticket is missing or malformed");
      const hash = await sha256hex(ticket);
      this.sql.exec("DELETE FROM tickets WHERE expires < ?", Date.now());
      const found = this.sql.exec("SELECT hash FROM tickets WHERE hash = ?", hash).toArray().length > 0;
      if (!found) return text(401, "this join link was used already or has expired; make a new one");
      this.sql.exec("DELETE FROM tickets WHERE hash = ?", hash);
      const count = Number(this.sql.exec("SELECT count(*) AS n FROM devices").one().n);
      if (count >= MAX_DEVICES) return text(429, `at most ${MAX_DEVICES} devices; remove one first`);
      const tokenHash = await sha256hex(token);
      if (this.sql.exec("SELECT id FROM devices WHERE token = ?", tokenHash).toArray().length) {
        return text(409, "that token is in use");
      }
      const id = randomHex(8);
      this.addDevice(id, deviceName(req.headers.get("x-device-name")), tokenHash);
      return json({ device: id }, 201);
    }

    // Same answer for "no such mailbox" and "wrong token", so the id alone
    // tells a stranger nothing.
    const me = await this.device(token);
    if (me === null) return text(401, "unknown mailbox or wrong token");

    const version = this.version();
    switch (`${req.method} ${sub}`) {
      case "GET ":
      case "HEAD ": {
        const headers = { etag: etag(version), "cache-control": "no-store" };
        if (parseTag(req.headers.get("if-none-match")) === version) {
          return new Response(null, { status: 304, headers });
        }
        if (version === 0) return new Response(null, { status: 204, headers });
        return new Response(req.method === "HEAD" ? null : this.load(), {
          headers: { ...headers, "content-type": "application/octet-stream" },
        });
      }
      case "PUT ": {
        const want = parseTag(req.headers.get("if-match"));
        if (want === null) return text(428, "If-Match with the version you merged from is required");
        if (want !== version) return text(412, "someone saved first: fetch, merge, try again", { etag: etag(version) });
        if (this.rateLimited()) return text(429, "too many saves; wait a minute", { "retry-after": "60" });
        const body = await this.readBody(req);
        if (body instanceof Response) return body;
        this.store(body, version + 1);
        this.notify(version + 1);
        return text(200, "saved", { etag: etag(version + 1) });
      }
      case "DELETE ": {
        for (const ws of this.ctx.getWebSockets()) ws.close(4004, "mailbox deleted");
        await this.ctx.storage.deleteAll();
        this.schema();
        return new Response(null, { status: 204 });
      }
      case "POST tickets": {
        const now = Date.now();
        this.sql.exec("DELETE FROM tickets WHERE expires < ?", now);
        const n = Number(this.sql.exec("SELECT count(*) AS n FROM tickets").one().n);
        if (n >= MAX_TICKETS) return text(429, "too many unused join links; wait ten minutes");
        const ticket = randomToken();
        const expires = now + TICKET_SECONDS * 1000;
        this.sql.exec("INSERT INTO tickets (hash, expires) VALUES (?, ?)", await sha256hex(ticket), expires);
        return json({ ticket, expires: Math.floor(expires / 1000) }, 201);
      }
      case "GET devices": {
        const rows = this.sql.exec("SELECT id, name, created, seen FROM devices ORDER BY created").toArray();
        return json(
          rows.map((r) => ({
            id: r.id,
            name: r.name,
            created: Math.floor(Number(r.created) / 1000),
            lastSeen: Math.floor(Number(r.seen) / 1000),
            current: r.id === me,
          })),
        );
      }
      case "DELETE devices": {
        if (!arg || !DEVICE_RE.test(arg)) return text(400, "device id must be 16 hex characters");
        const gone = this.sql.exec("SELECT id FROM devices WHERE id = ?", arg).toArray().length > 0;
        if (!gone) return text(404, "no such device");
        this.sql.exec("DELETE FROM devices WHERE id = ?", arg);
        for (const ws of this.ctx.getWebSockets(arg)) ws.close(4001, "device removed");
        return new Response(null, { status: 204 });
      }
      case "GET watch": {
        if (req.headers.get("upgrade")?.toLowerCase() !== "websocket") return text(426, "WebSocket upgrade required");
        if (this.ctx.getWebSockets().length >= MAX_WATCHERS) return text(429, "too many open watchers");
        const pair = new WebSocketPair();
        // Tagged with the device, so removing it closes its sockets.
        this.ctx.acceptWebSocket(pair[1], [me]);
        pair[1].send(JSON.stringify({ version }));
        return new Response(null, { status: 101, webSocket: pair[0] });
      }
      default:
        return text(405, "method not allowed");
    }
  }

  async webSocketMessage() {
    // Clients only listen; "ping" is answered by the auto-response above.
  }

  /** @param {WebSocket} ws @param {number} code */
  async webSocketClose(ws, code) {
    try {
      ws.close(code === 1005 ? 1000 : code, "bye");
    } catch {
      // Already closed.
    }
  }
}
