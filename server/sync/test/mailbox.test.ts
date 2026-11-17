import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { MAX_FILE, MAX_WRITES_PER_MINUTE } from "../src/index";

const BASE = "https://sync.example.com/v1/m/";
const CREATE_KEY = "test-create-key";

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

async function create(file: Uint8Array = bytes(4096)): Promise<{ id: string; token: string }> {
  const id = randomId();
  const token = randomToken();
  const r = await call(id, { method: "POST", token, body: file, headers: { "x-create-key": CREATE_KEY } });
  expect(r.status).toBe(201);
  expect(r.headers.get("etag")).toBe('"1"');
  return { id, token };
}

describe("creating a mailbox", () => {
  it("needs the create key", async () => {
    const token = randomToken();
    const id = randomId();
    expect((await call(id, { method: "POST", token, body: bytes(10) })).status).toBe(403);
    expect(
      (await call(id, { method: "POST", token, body: bytes(10), headers: { "x-create-key": "wrong" } })).status,
    ).toBe(403);
  });

  it("refuses a second create and bad ids or tokens", async () => {
    const { id, token } = await create();
    const again = await call(id, { method: "POST", token, body: bytes(10), headers: { "x-create-key": CREATE_KEY } });
    expect(again.status).toBe(409);
    expect((await call("NOT-HEX", { token })).status).toBe(400);
    expect((await call(id, { token: "short" })).status).toBe(401);
  });

  it("refuses plain http", async () => {
    const r = await exports.default.fetch(new Request("http://sync.example.com/v1"));
    expect(r.status).toBe(400);
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
    const { id, token } = await create();
    let v = 1;
    for (let i = 0; i < MAX_WRITES_PER_MINUTE; i++) {
      const r = await call(id, { method: "PUT", token, body: bytes(10), headers: { "if-match": `"${v}"` } });
      expect(r.status).toBe(200);
      v++;
    }
    const r = await call(id, { method: "PUT", token, body: bytes(10), headers: { "if-match": `"${v}"` } });
    expect(r.status).toBe(429);
  });
});

describe("tokens and deleting", () => {
  it("replacing the token locks out the old one", async () => {
    const { id, token } = await create();
    const next = randomToken();
    expect((await call(`${id}/token`, { method: "POST", token, headers: { "x-new-token": "bad" } })).status).toBe(400);
    expect((await call(`${id}/token`, { method: "POST", token, headers: { "x-new-token": next } })).status).toBe(204);
    expect((await call(id, { token })).status).toBe(401);
    expect((await call(id, { token: next })).status).toBe(200);
  });

  it("delete removes the file", async () => {
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

  it("needs a WebSocket upgrade and a valid token", async () => {
    const { id, token } = await create();
    expect((await call(`${id}/watch`, { token })).status).toBe(426);
    expect((await call(`${id}/watch`, { token: randomToken(), headers: { upgrade: "websocket" } })).status).toBe(401);
  });
});
