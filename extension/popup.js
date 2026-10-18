const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);
const ask = (msg) => api.runtime.sendMessage(msg);
const say = (text) => ($("message").textContent = text || "");

function row(item) {
  const li = document.createElement("li");
  const who = document.createElement("div");
  who.className = "who";
  const title = document.createElement("b");
  title.textContent = item.title;
  const user = document.createElement("span");
  user.textContent = item.username;
  who.append(title, user);
  const fill = document.createElement("button");
  fill.className = "fill";
  fill.textContent = "Fill";
  fill.onclick = async () => {
    const r = await ask({ type: "fill", id: item.id });
    if (r.ok) return window.close();
    if (r.crossOrigin) return offerFrames(item, r.crossOrigin);
    say(r.error);
  };
  li.append(who, fill);
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
  const s = await ask({ type: "status" });
  if (!s.ok) return say(s.error);
  if (!s.initialized) return say("No vault yet. Run `vault init` in a terminal.");
  $("connect").hidden = s.paired;
  if (!s.paired) return;
  $("unlock").hidden = s.unlocked;
  $("lock").hidden = !s.unlocked;
  if (!s.unlocked) return $("password").focus();
  const r = await ask({ type: "list" });
  $("origin").textContent = r.origin || "";
  if (!r.ok) return say(r.error);
  if (!r.items.length) return say("No saved login for this site.");
  $("items").append(...r.items.map(row));
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
$("generate").onclick = async () => {
  const r = await ask({ type: "generate" });
  if (!r.ok) return say(r.error);
  await navigator.clipboard.writeText(r.password);
  say("A new 24-character password was copied.");
};

refresh();
