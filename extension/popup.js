const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);
const ask = (msg) => api.runtime.sendMessage(msg);
const say = (text) => ($("message").textContent = text || "");

function who(item) {
  const div = document.createElement("div");
  div.className = "who";
  const title = document.createElement("b");
  title.textContent = item.title;
  const sub = document.createElement("span");
  sub.textContent = item.subtitle;
  div.append(title, sub);
  return div;
}

// A card or address row. A card is released only after the user confirms in
// vaultd's window, which may close this popup; the fill still completes.
function formRow(item) {
  const li = document.createElement("li");
  const fill = document.createElement("button");
  fill.className = "fill";
  fill.textContent = "Fill";
  fill.onclick = async () => {
    const card = item.kind === "card";
    if (card) say("Confirm in the Secret Vault window.");
    const r = await ask({ type: card ? "fillCard" : "fillIdentity", id: item.id });
    if (r.ok) return window.close();
    say(r.error);
  };
  li.append(who(item), fill);
  return li;
}

function section(title, items) {
  if (!items.length) return [];
  const h = document.createElement("h2");
  h.textContent = title;
  const ul = document.createElement("ul");
  ul.append(...items.map(formRow));
  return [h, ul];
}

function row(item) {
  const li = document.createElement("li");
  const fill = document.createElement("button");
  fill.className = "fill";
  fill.textContent = "Fill";
  fill.onclick = async () => {
    const r = await ask({ type: "fill", id: item.id });
    if (r.ok) return window.close();
    if (r.crossOrigin) return offerFrames(item, r.crossOrigin);
    say(r.error);
  };
  li.append(who(item), fill);
  if (item.hasTotp) {
    const totp = document.createElement("button");
    totp.textContent = "Code";
    totp.title = "Copy the one-time code";
    totp.onclick = async () => {
      const r = await ask({ type: "totp", id: item.id });
      if (!r.ok) return say(r.error);
      await navigator.clipboard.writeText(r.code);
      say(`Code copied (${r.remaining} s left).`);
    };
    li.append(totp);
  }
  return li;
}

// The form may sit in a frame from another site (a bank's login widget, or an
// attacker's iframe). Say which site, and fill there only if the user agrees.
function offerFrames(item, origins) {
  const box = $("frames");
  box.replaceChildren();
  const p = document.createElement("p");
  p.textContent = `The login form may be in a frame from another site. Only fill it if you trust that site with your ${item.title} login.`;
  box.append(p);
  for (const origin of origins) {
    const b = document.createElement("button");
    b.textContent = `Fill in ${origin}`;
    b.onclick = async () => {
      // Requesting the permission here is what lets the browser show its own prompt.
      if (!(await api.permissions.request({ origins: [`${origin}/*`] }))) return say("Not filled.");
      const r = await ask({ type: "fillFrame", id: item.id, frameOrigin: origin });
      if (r.ok) window.close();
      else say(r.error);
    };
    box.append(b);
  }
  box.hidden = false;
}

async function refresh() {
  say("");
  $("items").replaceChildren();
  $("forms").replaceChildren();
  const s = await ask({ type: "status" });
  if (!s.ok) return say(s.error);
  if (!s.initialized) return say("No vault yet. Run `vault init` in a terminal.");
  $("connect").hidden = s.paired;
  if (!s.paired) return;
  $("unlock").hidden = s.unlocked;
  $("lock").hidden = !s.unlocked;
  if (!s.unlocked) return $("password").focus();
  const [r, f] = await Promise.all([ask({ type: "list" }), ask({ type: "forms" })]);
  $("origin").textContent = r.origin || "";
  if (!r.ok) return say(r.error);
  $("items").append(...r.items.map(row));
  if (f.ok) {
    $("forms").append(
      ...section("Cards", f.items.filter((i) => i.kind === "card")),
      ...section("Addresses", f.items.filter((i) => i.kind === "identity")),
    );
  }
  if (!r.items.length && !$("forms").childElementCount) say("No saved login for this site.");
}

$("unlock").onsubmit = async (e) => {
  e.preventDefault();
  const password = $("password").value;
  $("password").value = "";
  const r = await ask({ type: "unlock", password });
  if (!r.ok) return say(r.error);
  refresh();
};
$("pair").onclick = async () => {
  $("pair").disabled = true;
  say("Approve the request in the window vaultd opened.");
  const r = await ask({ type: "pair" });
  $("pair").disabled = false;
  if (!r.ok) return say(r.error);
  refresh();
};
$("lock").onclick = async () => {
  await ask({ type: "lock" });
  refresh();
};
const generated = {
  random: "A new 24-character password was copied.",
  words: "Three random words were copied.",
  apple: "A new password in the xxxxxx-xxxxxx-xxxxxx style was copied.",
};
$("generate").onclick = async () => {
  const style = $("style").value;
  const r = await ask({ type: "generate", style });
  if (!r.ok) return say(r.error);
  await navigator.clipboard.writeText(r.password);
  say(generated[style]);
};

refresh();
