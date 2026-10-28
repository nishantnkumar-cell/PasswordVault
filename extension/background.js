// Background script: the only part of the extension that talks to the vault.
// It takes the page origin from the browser's own tab and frame data, never
// from page content, and fills only on a user gesture (the popup or the
// keyboard command), in the top frame and same-origin frames. Cards and
// addresses are filled only into the top frame of https pages, and a card
// only after the user confirms in vaultd's own window.

import { crossOriginFrames, fillableFrames, framesWithOrigin, fromPopup, originOf } from "./lib/policy.js";
import { fillInPage } from "./lib/fill.js";

const HOST = "dev.passwordvault.host";
const api = globalThis.browser ?? globalThis.chrome;

async function host(msg) {
  try {
    return await api.runtime.sendNativeMessage(HOST, msg);
  } catch (e) {
    return { ok: false, error: `cannot reach the vault host (${e.message}); see docs/browser.md` };
  }
}

async function activeTab() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  const origin = tab && originOf(tab.url);
  if (!origin) throw new Error("this page cannot be filled");
  return { tab, origin };
}

async function inject(tabId, frameIds, expectedOrigin, item) {
  if (!frameIds.length) return 0;
  const results = await api.scripting.executeScript({
    target: { tabId, frameIds },
    func: fillInPage,
    args: [expectedOrigin, item.username, item.password],
  });
  return results.reduce((n, r) => n + (r.result || 0), 0);
}

// The item is always released for the tab's own origin; the frame origin
// only decides where it is typed, after the user confirmed that origin.
async function fill(id, frameOrigin) {
  const { tab, origin } = await activeTab();
  const item = await host({ type: "fill", id, origin });
  if (!item.ok) return item;
  const frames = await api.webNavigation.getAllFrames({ tabId: tab.id });
  if (frameOrigin) {
    try {
      const filled = await inject(tab.id, framesWithOrigin(frames, frameOrigin), frameOrigin, item);
      return filled ? { ok: true, filled } : { ok: false, error: `no visible login form in the frame from ${frameOrigin}` };
    } finally {
      await api.permissions.remove({ origins: [`${frameOrigin}/*`] }).catch(() => {});
    }
  }
  const filled = await inject(tab.id, fillableFrames(frames, origin), origin, item);
  if (filled) return { ok: true, filled };
  const others = crossOriginFrames(frames, origin);
  if (others.length) return { ok: false, crossOrigin: others, error: "no visible login form on this page itself" };
  return { ok: false, error: "no visible login form on this page" };
}

// The card and address helpers, in the extension's isolated world of the
// tab's top frame (repeat injections are harmless).
async function inPage(tabId, func, args = []) {
  await api.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ["lib/form-inject.js"] });
  const [r] = await api.scripting.executeScript({ target: { tabId, frameIds: [0] }, func, args });
  return r?.result;
}

// Cards and identities to offer, if this https page has fields for them.
async function forms() {
  const { tab, origin } = await activeTab();
  if (!origin.startsWith("https:")) return { ok: true, items: [], card: false, identity: false };
  let found = { card: false, identity: false };
  try {
    found = (await inPage(tab.id, () => globalThis.__secretVault.detect())) ?? found;
  } catch {
    // A page the extension may not script.
  }
  if (!found.card && !found.identity) return { ok: true, items: [], ...found };
  const r = await host({ type: "forms", origin });
  if (!r.ok) return r;
  const items = r.items.filter((i) => (i.kind === "card" && found.card) || (i.kind === "identity" && found.identity));
  return { ok: true, items, ...found };
}

async function fillForm(kind, id) {
  const { tab, origin } = await activeTab();
  if (!origin.startsWith("https:")) return { ok: false, error: "cards and addresses are filled only on https pages" };
  const r = await host({ type: kind === "card" ? "fillCard" : "fillIdentity", id, origin });
  if (!r.ok) return r;
  const filled = await inPage(tab.id, (o, k, d) => globalThis.__secretVault.fillForm(o, k, d), [origin, kind, r.card ?? r.identity]);
  return filled ? { ok: true, filled } : { ok: false, error: `no ${kind === "card" ? "card" : "address"} fields to fill on this page` };
}

async function handle(msg) {
  switch (msg.type) {
    case "status":
      return host({ type: "status" });
    case "pair":
      return host({ type: "pair" });
    case "unlock":
      return host({ type: "unlock", password: msg.password });
    case "lock":
      return host({ type: "lock" });
    case "list": {
      const { origin } = await activeTab();
      return { ...(await host({ type: "find", origin })), origin };
    }
    case "fill":
      return fill(msg.id);
    case "fillFrame":
      return fill(msg.id, msg.frameOrigin);
    case "totp": {
      const { origin } = await activeTab();
      return host({ type: "totp", id: msg.id, origin });
    }
    case "forms":
      return forms();
    case "fillCard":
      return fillForm("card", msg.id);
    case "fillIdentity":
      return fillForm("identity", msg.id);
    case "generate":
      return host({
        type: "generate",
        length: 24,
        style: ["random", "words", "apple"].includes(msg.style) ? msg.style : "random",
      });
    default:
      return { ok: false, error: "unknown request" };
  }
}

api.runtime.onMessage.addListener((msg, sender, respond) => {
  if (!fromPopup(sender, api.runtime.id, api.runtime.getURL("popup.html"))) return false;
  handle(msg).then(respond, (e) => respond({ ok: false, error: e.message }));
  return true;
});

// Keyboard command: fill when exactly one login matches this site.
api.commands.onCommand.addListener(async (command) => {
  if (command !== "fill-login") return;
  try {
    const { origin } = await activeTab();
    const found = await host({ type: "find", origin });
    if (found.ok && found.items.length === 1) await fill(found.items[0].id);
  } catch {
    // Nothing to fill on this page.
  }
});
