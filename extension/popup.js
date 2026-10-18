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
    if (r.ok) window.close();
    else say(r.error);
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

async function refresh() {
  say("");
  $("items").replaceChildren();
  const s = await ask({ type: "status" });
  if (!s.ok) return say(s.error);
  if (!s.initialized) return say("No vault yet. Run `vault init` in a terminal.");
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
