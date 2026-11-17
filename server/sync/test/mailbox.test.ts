import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

// The server's limits (src/index.js), which it may not export.
const MAX_FILE = 4 * 1024 * 1024;
const MAX_TICKETS = 5;
const MAX_WRITES_PER_MINUTE = 60;
const REVISION = 1;

const ORIGIN = "https://sync.example.com";
const BASE = `${ORIGIN}/v1/m/`;
const ADMIN_KEY = "test-admin-key";

function randomId(): string {
  return [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomToken(): string {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function bytes(n: number, fill = 7): Uint8Array {
  return new Uint8Array(n).fill(fill);
}

async function call(path: string, init: RequestInit & { token?: string } = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (init.token) headers.set("authorization", `Bearer ${init.token}`);
  return exports.default.fetch(new Request(BASE + path, { ...init, headers }));
}

/** A mailbox holding `file` (version 1), and its first device's token. */
async function create(file: Uint8Array | null = bytes(4096)): Promise<{ id: string; token: string; device: string }> {
  const id = randomId();
  const token = randomToken();
  const r = await call(id, { method: "POST", token, headers: { "x-admin-key": ADMIN_KEY, "x-device-name": "Laptop" } });
  expect(r.status).toBe(201);
  const { device } = (await r.json()) as { device: string };
  expect(device).toMatch(/^[0-9a-f]{16}$/);
  if (file) {
    const put = await call(id, { method: "PUT", token, body: file, headers: { "if-match": '"0"' } });
    expect(put.status).toBe(200);
  }
  return { id, token, device };
}

async function join(id: string, token: string, name = "Phone"): Promise<{ token: string; device: string }> {
  const t = await call(`${id}/tickets`, { method: "POST", token });
  expect(t.status).toBe(201);
  const { ticket } = (await t.json()) as { ticket: string };
  const mine = randomToken();
  const r = await call(`${id}/join`, { method: "POST", token: mine, headers: { "x-ticket": ticket, "x-device-name": name } });
  expect(r.status).toBe(201);
  const { device } = (await r.json()) as { device: string };
  return { token: mine, device };
}

describe("the server", () => {
  it("exports only what the Workers runtime accepts", async () => {
    const mod = await import("../src/index.js");
    expect(Object.keys(mod).sort()).toEqual(["Mailbox", "default"]);
  });

  it("says what it is", async () => {
    const r = await exports.default.fetch(new Request(`${ORIGIN}/`));
    expect(await r.json()).toEqual({ service: "secret-vault-sync", api: 1, revision: REVISION });
    const page = await exports.default.fetch(new Request(`${ORIGIN}/join`));
    expect(await page.text()).toContain("Join a Secret Vault");
  });

  it("refuses plain http", async () => {
    const r = await exports.default.fetch(new Request("http://sync.example.com/v1"));
    expect(r.status).toBe(400);
  });
});

describe("creating a mailbox", () => {
  it("needs the admin key", async () => {
    const token = randomToken();
    const id = randomId();
    expect((await call(id, { method: "POST", token })).status).toBe(403);
    expect((await call(id, { method: "POST", token, headers: { "x-admin-key": "wrong" } })).status).toBe(403);
  });

  it("starts empty and refuses a second create and bad ids or tokens", async () => {
    const { id, token } = await create(null);
    const empty = await call(id, { token });
    expect(empty.status).toBe(204);
    expect(empty.headers.get("etag")).toBe('"0"');
    const again = await call(id, { method: "POST", token, headers: { "x-admin-key": ADMIN_KEY } });
    expect(again.status).toBe(409);
    expect((await call("NOT-HEX", { token })).status).toBe(400);
    expect((await call(id, { token: "short" })).status).toBe(401);
  });
});

describe("reading and writing", () => {
  it("returns the file with its version and 304 when unchanged", async () => {
    const file = bytes(8192, 3);
    const { id, token } = await create(file);
    const r = await call(id, { token });
    expect(r.status).toBe(200);
    expect(r.headers.get("etag")).toBe('"1"');
    expect(new Uint8Array(await r.arrayBuffer())).toEqual(file);
    const same = await call(id, { token, headers: { "if-none-match": '"1"' } });
    expect(same.status).toBe(304);
  });

  it("answers a wrong token and an unknown mailbox the same way", async () => {
    const { id } = await create();
    expect((await call(id, { token: randomToken() })).status).toBe(401);
    expect((await call(randomId(), { token: randomToken() })).status).toBe(401);
  });

  it("saves only on top of the version the client merged from", async () => {
    const { id, token } = await create();
    expect((await call(id, { method: "PUT", token, body: bytes(10) })).status).toBe(428);

    const ok = await call(id, { method: "PUT", token, body: bytes(10, 1), headers: { "if-match": '"1"' } });
    expect(ok.status).toBe(200);
    expect(ok.headers.get("etag")).toBe('"2"');

    // A second device that also started from version 1 loses the race.
    const late = await call(id, { method: "PUT", token, body: bytes(10, 2), headers: { "if-match": '"1"' } });
    expect(late.status).toBe(412);
    expect(late.headers.get("etag")).toBe('"2"');

    const now = await call(id, { token });
    expect(new Uint8Array(await now.arrayBuffer())).toEqual(bytes(10, 1));
  });

  it("keeps files larger than one storage row", async () => {
    const big = new Uint8Array(3 * 1024 * 1024 + 17);
    for (let i = 0; i < big.length; i++) big[i] = i % 251;
    const { id, token } = await create(big);
    const r = await call(id, { token });
    expect(new Uint8Array(await r.arrayBuffer())).toEqual(big);
  });

  it("refuses files over the size limit and empty files", async () => {
    const { id, token } = await create();
    const tooBig = await call(id, { method: "PUT", token, body: bytes(MAX_FILE + 1), headers: { "if-match": '"1"' } });
    expect(tooBig.status).toBe(413);
    const empty = await call(id, { method: "PUT", token, body: new Uint8Array(0), headers: { "if-match": '"1"' } });
    expect(empty.status).toBe(400);
  });

  it("limits saves per minute", async () => {
    const { id, token } = await create(null);
    let v = 0;
    for (let i = 0; i < MAX_WRITES_PER_MINUTE; i++) {
      const r = await call(id, { method: "PUT", token, body: bytes(10), headers: { "if-match": `"${v}"` } });
      expect(r.status).toBe(200);
      v++;
    }
    const r = await call(id, { method: "PUT", token, body: bytes(10), headers: { "if-match": `"${v}"` } });
    expect(r.status).toBe(429);
  });
});

describe("devices", () => {
  it("joins a device with a one-time ticket", async () => {
    const { id, token, device } = await create();
    const phone = await join(id, token);
    expect((await call(id, { token: phone.token })).status).toBe(200);

    const r = await call(`${id}/devices`, { token: phone.token });
    const list = (await r.json()) as { id: string; name: string; current: boolean }[];
    expect(list.map((d) => [d.id, d.name, d.current])).toEqual([
      [device, "Laptop", false],
      [phone.device, "Phone", true],
    ]);
  });

  it("refuses a used, made-up or missing ticket", async () => {
    const { id, token } = await create();
    const t = await call(`${id}/tickets`, { method: "POST", token });
    const { ticket } = (await t.json()) as { ticket: string };
    const first = await call(`${id}/join`, { method: "POST", token: randomToken(), headers: { "x-ticket": ticket } });
    expect(first.status).toBe(201);
    const second = await call(`${id}/join`, { method: "POST", token: randomToken(), headers: { "x-ticket": ticket } });
    expect(second.status).toBe(401);
    const madeUp = await call(`${id}/join`, { method: "POST", token: randomToken(), headers: { "x-ticket": randomToken() } });
    expect(madeUp.status).toBe(401);
    expect((await call(`${id}/join`, { method: "POST", token: randomToken() })).status).toBe(400);
    // Only a device can ask for a ticket.
    expect((await call(`${id}/tickets`, { method: "POST", token: randomToken() })).status).toBe(401);
  });

  it("limits unused tickets", async () => {
    const { id, token } = await create();
    for (let i = 0; i < MAX_TICKETS; i++) {
      expect((await call(`${id}/tickets`, { method: "POST", token })).status).toBe(201);
    }
    expect((await call(`${id}/tickets`, { method: "POST", token })).status).toBe(429);
  });

  it("removing a device locks it out", async () => {
    const { id, token } = await create();
    const phone = await join(id, token);
    expect((await call(`${id}/devices/zz`, { method: "DELETE", token })).status).toBe(400);
    expect((await call(`${id}/devices/${phone.device}`, { method: "DELETE", token })).status).toBe(204);
    expect((await call(id, { token: phone.token })).status).toBe(401);
    expect((await call(id, { token })).status).toBe(200);
  });

  it("delete removes the mailbox", async () => {
    const { id, token } = await create();
    expect((await call(id, { method: "DELETE", token })).status).toBe(204);
    expect((await call(id, { token })).status).toBe(401);
  });
});

describe("watching for changes", () => {
  it("sends the version on connect and after each save", async () => {
    const { id, token } = await create();
    const r = await call(`${id}/watch`, { token, headers: { upgrade: "websocket" } });
    expect(r.status).toBe(101);
    const ws = r.webSocket!;
    const seen: number[] = [];
    const got = new Promise<void>((resolve) => {
      ws.addEventListener("message", (e) => {
        seen.push(JSON.parse(e.data as string).version);
        if (seen.length === 2) resolve();
      });
    });
    ws.accept();
    await call(id, { method: "PUT", token, body: bytes(10), headers: { "if-match": '"1"' } });
    await got;
    expect(seen).toEqual([1, 2]);
    ws.close();
  });

  it("closes a removed device's socket", async () => {
    const { id, token } = await create();
    const phone = await join(id, token);
    const r = await call(`${id}/watch`, { token: phone.token, headers: { upgrade: "websocket" } });
    const ws = r.webSocket!;
    const closed = new Promise<number>((resolve) => ws.addEventListener("close", (e) => resolve(e.code)));
    ws.accept();
    await call(`${id}/devices/${phone.device}`, { method: "DELETE", token });
    expect(await closed).toBe(4001);
  });

  it("needs a WebSocket upgrade and a valid token", async () => {
    const { id, token } = await create();
    expect((await call(`${id}/watch`, { token })).status).toBe(426);
    expect((await call(`${id}/watch`, { token: randomToken(), headers: { upgrade: "websocket" } })).status).toBe(401);
  });
});
