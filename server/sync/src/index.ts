// Secret Vault cloud sync server: a versioned mailbox for one encrypted vault
// file per vault (docs/cloud-sync.md). The server never sees a key: it keeps
// the file the client uploads, a version number and the SHA-256 of a random
// access token. Merging, the header MAC and the refusal of old or retired
// copies all happen in the client (docs/format.md 5.1).
//
// API (every call but the root needs "Authorization: Bearer <token>"):
//   POST   /v1/m/<id>        create; body = file; also needs X-Create-Key
//   GET    /v1/m/<id>        the file; ETag "<version>"; If-None-Match -> 304
//   PUT    /v1/m/<id>        replace; If-Match "<version>" required, else 428;
//                            412 (with the current ETag) when someone wrote first
//   DELETE /v1/m/<id>        delete the mailbox and its file
//   POST   /v1/m/<id>/token  replace the token with X-New-Token
//   GET    /v1/m/<id>/watch  WebSocket; sends {"version":n} on connect and on
//                            every change; "ping" is answered "pong"

import { DurableObject } from "cloudflare:workers";

export interface Env {
  MAILBOX: DurableObjectNamespace<Mailbox>;
  /** Needed to create a mailbox, so strangers cannot use up the free plan. */
  CREATE_KEY?: string;
}

/** Largest vault file accepted. Vaults with thousands of items are < 1 MiB. */
export const MAX_FILE = 4 * 1024 * 1024;
/** SQLite rows in a Durable Object are limited to 2 MB. */
const CHUNK = 1024 * 1024;
/** Saves per mailbox per minute before 429. */
export const MAX_WRITES_PER_MINUTE = 60;
/** Open watch sockets per mailbox. */
export const MAX_WATCHERS = 32;

const ID_RE = /^[0-9a-f]{32}$/;
/** 256-bit tokens in base64url are 43 characters. */
const TOKEN_RE = /^[A-Za-z0-9_-]{43,128}$/;

const enc = new TextEncoder();

async function sha256(s: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", enc.encode(s));
}

function hex(b: ArrayBuffer): string {
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** Compares two secrets without leaking where they differ. */
async function sameSecret(a: string, b: string): Promise<boolean> {
  const [x, y] = await Promise.all([sha256(a), sha256(b)]);
  return crypto.subtle.timingSafeEqual(x, y);
}

function text(status: number, body: string, headers: HeadersInit = {}): Response {
  return new Response(body + "\n", {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}

function etag(version: number): string {
  return `"${version}"`;
}

/** "12", "\"12\"" or W/"12" -> 12; anything else -> null. */
function parseTag(h: string | null): number | null {
  if (h === null) return null;
  const m = h.trim().match(/^(?:W\/)?"?(\d{1,15})"?$/);
  return m ? Number(m[1]) : null;
}

function bearer(req: Request): string | null {
  const m = (req.headers.get("authorization") ?? "").match(/^Bearer ([A-Za-z0-9_-]+)$/);
  return m && TOKEN_RE.test(m[1]) ? m[1] : null;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.protocol !== "https:") return text(400, "use https");
    if (url.pathname === "/" || url.pathname === "/v1") {
      return Response.json({ service: "secret-vault-sync", api: 1 }, { headers: { "cache-control": "no-store" } });
    }
    const m = url.pathname.match(/^\/v1\/m\/([^/]+)(\/watch|\/token)?$/);
    if (!m) return text(404, "not found");
    if (!ID_RE.test(m[1])) return text(400, "mailbox id must be 32 lowercase hex characters");
    if (req.method === "POST" && m[2] === undefined) {
      if (!env.CREATE_KEY) return text(403, "creating mailboxes is turned off on this server (no CREATE_KEY)");
      if (!(await sameSecret(req.headers.get("x-create-key") ?? "", env.CREATE_KEY))) {
        return text(403, "wrong create key");
      }
    }
    if (bearer(req) === null) return text(401, "missing or malformed token");
    const stub = env.MAILBOX.get(env.MAILBOX.idFromName(m[1]));
    return stub.fetch(req);
  },
} satisfies ExportedHandler<Env>;

/** One vault's mailbox. Requests to one Durable Object run one at a time, so
 * the version check and the write below cannot interleave with another. */
export class Mailbox extends DurableObject<Env> {
  private sql: SqlStorage;
  private writes: number[] = [];

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.schema();
    // Pings are answered without waking the object (no duration charge).
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  private schema(): void {
    this.sql.exec("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)");
    this.sql.exec("CREATE TABLE IF NOT EXISTS chunks (i INTEGER PRIMARY KEY, data BLOB NOT NULL)");
  }

  private meta(k: string): string | null {
    const rows = this.sql.exec<{ v: string }>("SELECT v FROM meta WHERE k = ?", k).toArray();
    return rows.length ? rows[0].v : null;
  }

  private setMeta(k: string, v: string): void {
    this.sql.exec("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", k, v);
  }

  private version(): number {
    return Number(this.meta("version") ?? "0");
  }

  private store(file: ArrayBuffer, version: number): void {
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM chunks");
      for (let off = 0, i = 0; off < file.byteLength; off += CHUNK, i++) {
        this.sql.exec("INSERT INTO chunks (i, data) VALUES (?, ?)", i, file.slice(off, off + CHUNK));
      }
      this.setMeta("version", String(version));
      this.setMeta("updated", new Date().toISOString());
    });
  }

  private load(): Uint8Array {
    const parts = this.sql
      .exec<{ data: ArrayBuffer }>("SELECT data FROM chunks ORDER BY i")
      .toArray()
      .map((r) => new Uint8Array(r.data));
    const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
    let off = 0;
    for (const p of parts) {
      out.set(p, off);
      off += p.byteLength;
    }
    return out;
  }

  private async readBody(req: Request): Promise<ArrayBuffer | Response> {
    const declared = Number(req.headers.get("content-length") ?? "0");
    if (declared > MAX_FILE) return text(413, `file larger than ${MAX_FILE} bytes`);
    const body = await req.arrayBuffer();
    if (body.byteLength > MAX_FILE) return text(413, `file larger than ${MAX_FILE} bytes`);
    if (body.byteLength === 0) return text(400, "empty file");
    return body;
  }

  /** Sliding one-minute window, kept in memory: a soft limit against a
   * runaway client, not a security boundary. */
  private rateLimited(): boolean {
    const now = Date.now();
    this.writes = this.writes.filter((t) => now - t < 60_000);
    if (this.writes.length >= MAX_WRITES_PER_MINUTE) return true;
    this.writes.push(now);
    return false;
  }

  private notify(version: number): void {
    const msg = JSON.stringify({ version });
    for (const ws of this.ctx.getWebSockets()) {
      try {
        ws.send(msg);
      } catch {
        // A socket that is closing; the client reconnects and asks again.
      }
    }
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const sub = url.pathname.endsWith("/watch") ? "watch" : url.pathname.endsWith("/token") ? "token" : "";
    const token = bearer(req)!;
    const stored = this.meta("token");

    if (req.method === "POST" && sub === "") {
      if (stored !== null) return text(409, "mailbox already exists");
      const body = await this.readBody(req);
      if (body instanceof Response) return body;
      this.setMeta("token", hex(await sha256(token)));
      this.store(body, 1);
      return text(201, "created", { etag: etag(1) });
    }

    // Same answer for "no such mailbox" and "wrong token", so the id alone
    // tells a stranger nothing.
    if (stored === null || !crypto.subtle.timingSafeEqual(enc.encode(hex(await sha256(token))), enc.encode(stored))) {
      return text(401, "unknown mailbox or wrong token");
    }

    const version = this.version();
    switch (`${req.method} ${sub}`) {
      case "GET ":
      case "HEAD ": {
        if (parseTag(req.headers.get("if-none-match")) === version) {
          return new Response(null, { status: 304, headers: { etag: etag(version), "cache-control": "no-store" } });
        }
        return new Response(req.method === "HEAD" ? null : this.load(), {
          headers: { "content-type": "application/octet-stream", etag: etag(version), "cache-control": "no-store" },
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
      case "POST token": {
        const next = req.headers.get("x-new-token") ?? "";
        if (!TOKEN_RE.test(next)) return text(400, "X-New-Token must be a base64url token of 43 or more characters");
        this.setMeta("token", hex(await sha256(next)));
        // Sockets opened with the old token must not keep hearing about changes.
        for (const ws of this.ctx.getWebSockets()) ws.close(4001, "token replaced");
        return new Response(null, { status: 204 });
      }
      case "GET watch": {
        if (req.headers.get("upgrade")?.toLowerCase() !== "websocket") return text(426, "WebSocket upgrade required");
        if (this.ctx.getWebSockets().length >= MAX_WATCHERS) return text(429, "too many open watchers");
        const pair = new WebSocketPair();
        this.ctx.acceptWebSocket(pair[1]);
        pair[1].send(JSON.stringify({ version }));
        return new Response(null, { status: 101, webSocket: pair[0] });
      }
      default:
        return text(405, "method not allowed");
    }
  }

  async webSocketMessage(): Promise<void> {
    // Clients only listen; "ping" is answered by the auto-response above.
  }

  async webSocketClose(ws: WebSocket, code: number): Promise<void> {
    try {
      ws.close(code === 1005 ? 1000 : code, "bye");
    } catch {
      // Already closed.
    }
  }
}
