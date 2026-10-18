// Background script: the only part of the extension that talks to the vault.
// It takes the page origin from the browser's own tab and frame data, never
// from page content, and fills only on a user gesture (the popup or the
// keyboard command), in the top frame and same-origin frames.

import { fillableFrames, fromPopup, originOf } from "./lib/policy.js";
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

async function fill(id) {
  const { tab, origin } = await activeTab();
  const item = await host({ type: "fill", id, origin });
  if (!item.ok) return item;
  const frames = await api.webNavigation.getAllFrames({ tabId: tab.id });
  const results = await api.scripting.executeScript({
    target: { tabId: tab.id, frameIds: fillableFrames(frames, origin) },
    func: fillInPage,
    args: [origin, item.username, item.password],
  });
  const filled = results.reduce((n, r) => n + (r.result || 0), 0);
  return filled ? { ok: true, filled } : { ok: false, error: "no visible login form on this page" };
}

async function handle(msg) {
  switch (msg.type) {
    case "status":
      return host({ type: "status" });
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
    case "totp": {
      const { origin } = await activeTab();
      return host({ type: "totp", id: msg.id, origin });
    }
    case "generate":
      return host({ type: "generate", length: 24 });
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
