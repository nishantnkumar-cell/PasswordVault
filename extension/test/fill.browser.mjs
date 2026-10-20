// Browser test for the injected fill function and the packaged extension.
// Needs playwright-core and a full Chromium (not the headless shell):
//   PLAYWRIGHT_CORE=/path/to/playwright-core CHROMIUM=/path/to/chrome node test/fill.browser.mjs
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { fillInPage } from "../lib/fill.js";

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_CORE || "playwright-core");
const extDir = fileURLToPath(new URL("..", import.meta.url));

const PAGE = `<!doctype html><body>
<form id="decoy" style="position:absolute;left:-9999px"><input name="u1"><input type="password" name="p1"></form>
<div style="opacity:0"><input type="password" name="p2"></div>
<form id="real"><input type="email" name="user"><input type="hidden" name="csrf" value="t">
<input type="password" name="pass"><button>Sign in</button></form>
<input type="password" style="display:none" name="p3">
</body>`;

const server = createServer((req, res) => res.end(PAGE)).listen(0);
const url = `http://127.0.0.1:${server.address().port}/`;
const ctx = await chromium.launchPersistentContext("", {
  headless: true,
  executablePath: process.env.CHROMIUM || undefined,
  args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`],
});
try {
  const page = await ctx.newPage();
  await page.goto(url);
  const origin = new URL(url).origin;

  // Dummy values built at runtime, so secret scanners do not mistake them for credentials.
  const [user, pass] = ["test-user", "x".repeat(12)];
  const n = await page.evaluate(`(${fillInPage})(${JSON.stringify(origin)}, ${JSON.stringify(user)}, ${JSON.stringify(pass)})`);
  assert.equal(n, 2);
  const values = await page.evaluate(() =>
    Object.fromEntries([...document.querySelectorAll("input")].map((i) => [i.name, i.value])),
  );
  assert.equal(values.user, user);
  assert.equal(values.pass, pass);
  for (const decoy of ["u1", "p1", "p2", "p3"]) assert.equal(values[decoy], "", `${decoy} must stay empty`);
  assert.equal(values.csrf, "t");

  // A frame whose origin changed since the item was released is not filled.
  assert.equal(await page.evaluate(`(${fillInPage})("https://other.example", "a", "b")`), 0);

  // A login form inside a frame from another origin: filled only when the
  // expected origin is the frame's own (what the user confirmed), never the top's.
  const other = createServer((req, res) => res.end(PAGE)).listen(0);
  try {
    const frameUrl = `http://localhost:${other.address().port}/`;
    await page.setContent(`<iframe src="${frameUrl}" width="600" height="400"></iframe>`);
    const frame = page.frames().find((f) => f.url() === frameUrl) ?? (await page.waitForEvent("frameattached"));
    await frame.waitForLoadState();
    assert.equal(await frame.evaluate(`(${fillInPage})(${JSON.stringify(origin)}, "a", "b")`), 0);
    assert.equal(await frame.evaluate(`(${fillInPage})(${JSON.stringify(new URL(frameUrl).origin)}, "a", "b")`), 2);
  } finally {
    other.close();
  }

  // Card and address forms: the injected helper finds fields by autocomplete
  // attribute or by name and label, and leaves other fields alone.
  const CHECKOUT = `<!doctype html><body><form>
<label for="n">Name on card</label><input id="n">
<input name="cardnumber" autocomplete="cc-number">
<select name="exp_month"><option value="">Month</option><option value="06">June</option><option value="07">July</option></select>
<select name="exp_year"><option>2030</option><option>2031</option></select>
<input name="cvc" maxlength="4">
<input name="coupon">
<input name="given" autocomplete="shipping given-name"><input name="family" autocomplete="shipping family-name">
<input name="street" autocomplete="address-line1"><input name="zip" autocomplete="postal-code" value="KEEP">
<input name="email" type="email">
</form></body>`;
  await page.setContent(CHECKOUT);
  await page.addScriptTag({ path: fileURLToPath(new URL("../lib/form-inject.js", import.meta.url)) });
  assert.deepEqual(await page.evaluate(() => globalThis.__secretVault.detect()), { card: true, identity: true });
  const pageOrigin = await page.evaluate(() => location.origin);
  const card = { holder: "A Person", number: "4111111111111111", expMonth: 7, expYear: 2031, cvv: "123" };
  assert.equal(await page.evaluate(([o, d]) => globalThis.__secretVault.fillForm(o, "card", d), [pageOrigin, card]), 5);
  const after = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll("input,select")].map((i) => [i.name || i.id, i.value])));
  assert.equal(after.n, "A Person");
  assert.equal(after.cardnumber, card.number);
  assert.equal(after.exp_month, "07");
  assert.equal(after.exp_year, "2031");
  assert.equal(after.cvc, "123");
  assert.equal(after.coupon, "");
  assert.equal(after.given, "", "a card fill leaves the address alone");
  const id = { givenName: "Ada", familyName: "Lovelace", address1: "1 Main St", postcode: "N1", email: "ada@example.test" };
  assert.equal(await page.evaluate(([o, d]) => globalThis.__secretVault.fillForm(o, "identity", d), [pageOrigin, id]), 4);
  const after2 = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll("input")].map((i) => [i.name || i.id, i.value])));
  assert.deepEqual([after2.given, after2.family, after2.street, after2.email], ["Ada", "Lovelace", "1 Main St", "ada@example.test"]);
  assert.equal(after2.zip, "KEEP", "a filled-in address field is not overwritten");
  // Released for another origin: nothing is filled.
  assert.equal(await page.evaluate(([d]) => globalThis.__secretVault.fillForm("https://other.example", "card", d), [card]), 0);

  // The packaged extension loads and its background script starts.
  const worker = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent("serviceworker", { timeout: 10000 }));
  assert.match(worker.url(), /background\.js$/);
  console.log("browser tests passed");
} finally {
  await ctx.close();
  server.close();
}
