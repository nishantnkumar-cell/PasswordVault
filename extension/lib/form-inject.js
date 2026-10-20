// Card and address filling. Injected into the top frame with
// chrome.scripting.executeScript({ files }) before a fill, so it is a classic
// script that leaves its functions on the content script's own global (the
// extension's isolated world, which the page cannot see). Node loads it too,
// for test/form.test.mjs.
(() => {
  const CARD = new Set(["cc-name", "cc-number", "cc-csc", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-type"]);
  const IDENTITY = new Set([
    "name", "honorific-prefix", "given-name", "additional-name", "family-name", "organization",
    "email", "tel", "street-address", "address-line1", "address-line2", "address-line3",
    "address-level2", "address-level1", "postal-code", "country", "country-name",
  ]);
  // autocomplete tokens with the same meaning as one above.
  const ALIASES = { "cc-given-name": "cc-name", "cc-family-name": "cc-name", "tel-national": "tel" };

  // Guesses from the field's name, id, placeholder and label, for pages
  // without autocomplete attributes. Order matters: the first match wins.
  const RULES = [
    ["cc-name", /card.?holder|name.?on.?card|cc.?name|card.?name|holder.?name/i],
    ["cc-number", /card.?(number|num|no\b)|cc.?num|credit.?card|acct.?num/i],
    ["cc-csc", /cvv|cvc|csc|cvn|security.?code|card.?verification/i],
    ["cc-exp", /mm.?\/.?yy|exp.?date|valid.?(thru|until)/i],
    ["cc-exp-month", /exp\w*.?month|month|\bmm\b/i],
    ["cc-exp-year", /exp\w*.?year|year|\byy(yy)?\b/i],
    ["cc-exp", /expir/i],
    ["email", /e.?mail/i],
    ["tel", /phone|mobile|telephone|\btel\b/i],
    ["honorific-prefix", /honorific|salutation|\btitle\b/i],
    ["given-name", /first.?name|given.?name|fore.?name|\bfname\b/i],
    ["additional-name", /middle.?name|\bmname\b/i],
    ["family-name", /last.?name|family.?name|surname|\blname\b/i],
    ["organization", /company|organi[sz]ation|business/i],
    ["address-line2", /address.?(line)?.?2|addr.?2|apartment|suite|\bapt\b|flat/i],
    ["address-line3", /address.?(line)?.?3|addr.?3/i],
    ["address-line1", /address.?(line)?.?1|addr.?1|street|address/i],
    ["postal-code", /zip|post.?code|postal/i],
    ["address-level2", /city|town|locality|suburb/i],
    ["address-level1", /state|province|region|county/i],
    ["country", /country/i],
    ["name", /full.?name|^name$|your.?name/i],
  ];

  /**
   * What a field wants, as an autocomplete token, or null. `f` holds the
   * field's autocomplete, type, name, id, placeholder and label text.
   */
  function classifyField(f) {
    const tokens = String(f.autocomplete || "").toLowerCase().trim().split(/\s+/).filter(Boolean);
    const last = tokens.at(-1);
    if (last && last !== "off" && last !== "on") {
      const t = ALIASES[last] || last;
      if (CARD.has(t) || IDENTITY.has(t)) return t;
    }
    const type = String(f.type || "").toLowerCase();
    if (type === "email") return "email";
    if (type === "tel") return "tel";
    if (type === "password" || type === "hidden" || type === "checkbox" || type === "radio") return null;
    const text = [f.name, f.id, f.placeholder, f.label].filter(Boolean).join(" ");
    for (const [token, re] of RULES) if (re.test(text)) return token;
    return null;
  }

  const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
  const pad = (n) => String(n).padStart(2, "0");

  /**
   * The value for `token` from a card or identity, shaped by the field:
   * `hints.maxLength` and `hints.placeholder` pick two- or four-digit years.
   * Returns a list of acceptable values, best first ([] for none).
   */
  function valuesFor(token, kind, d, hints = {}) {
    const short = (hints.maxLength > 0 && hints.maxLength <= 2) || /\byy\b/i.test(hints.placeholder || "");
    if (kind === "card") {
      const m = d.expMonth || 0;
      const y = d.expYear || 0;
      switch (token) {
        case "cc-name": return [d.holder];
        case "cc-number": return [d.number];
        case "cc-csc": return [d.cvv];
        case "cc-type": return [d.brand];
        case "cc-exp-month": return m ? [pad(m), String(m), MONTHS[m - 1], MONTHS[m - 1].slice(0, 3)] : [];
        case "cc-exp-year": return y ? (short ? [pad(y % 100), String(y)] : [String(y), pad(y % 100)]) : [];
        case "cc-exp": {
          if (!m || !y) return [];
          const long = (hints.maxLength >= 7 && !short) || /yyyy/i.test(hints.placeholder || "");
          const sep = / \/ /.test(hints.placeholder || "") ? " / " : "/";
          return [`${pad(m)}${sep}${long ? y : pad(y % 100)}`];
        }
        default: return [];
      }
    }
    const lines = [d.address1, d.address2, d.address3].filter(Boolean);
    switch (token) {
      case "name": return [d.fullName];
      case "honorific-prefix": return [d.honorific];
      case "given-name": return [d.givenName];
      case "additional-name": return [d.middleName];
      case "family-name": return [d.familyName];
      case "organization": return [d.company];
      case "email": return [d.email];
      case "tel": return [d.phone];
      case "street-address": return [lines.join(hints.multiline ? "\n" : ", ")];
      case "address-line1": return [d.address1];
      case "address-line2": return [d.address2];
      case "address-line3": return [d.address3];
      case "address-level2": return [d.city];
      case "address-level1": return [d.region];
      case "postal-code": return [d.postcode];
      case "country": case "country-name": return [d.country];
      default: return [];
    }
  }

  function wanted(kind) {
    return kind === "card" ? CARD : IDENTITY;
  }

  // ---- In the page ----

  function visible(el) {
    if (el.disabled || el.readOnly || el.type === "hidden") return false;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
      const s = getComputedStyle(n);
      if (s.display === "none" || s.visibility === "hidden" || s.visibility === "collapse" || Number(s.opacity) < 0.1) return false;
    }
    return true;
  }

  function labelOf(el) {
    const parts = [];
    if (el.labels) for (const l of el.labels) parts.push(l.textContent);
    parts.push(el.getAttribute("aria-label"));
    const by = el.getAttribute("aria-labelledby");
    if (by) for (const id of by.split(/\s+/)) parts.push(document.getElementById(id)?.textContent);
    return parts.filter(Boolean).join(" ").trim();
  }

  function fields(kind) {
    const out = [];
    for (const el of document.querySelectorAll("input, select, textarea")) {
      if (!visible(el)) continue;
      const token = classifyField({
        autocomplete: el.getAttribute("autocomplete"),
        type: el.tagName === "INPUT" ? el.type : el.tagName.toLowerCase(),
        name: el.name,
        id: el.id,
        placeholder: el.getAttribute("placeholder"),
        label: labelOf(el),
      });
      if (token && wanted(kind).has(token)) out.push([el, token]);
    }
    return out;
  }

  // A page offers card filling only with a card number field, and address
  // filling only with a name or address field (an email box alone is a login).
  const CARD_SIGNS = new Set(["cc-number"]);
  const IDENTITY_SIGNS = new Set(["name", "given-name", "family-name", "street-address", "address-line1", "postal-code"]);

  /** Which kinds of form this page has, for the popup to offer. */
  function detect() {
    const has = (kind, signs) => fields(kind).some(([, t]) => signs.has(t));
    return { card: has("card", CARD_SIGNS), identity: has("identity", IDENTITY_SIGNS) };
  }

  function set(el, value) {
    const proto = el.tagName === "SELECT" ? HTMLSelectElement : el.tagName === "TEXTAREA" ? HTMLTextAreaElement : HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(proto.prototype, "value").set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.blur();
  }

  /**
   * Fill the page's card or address fields. Refuses if the page is no longer
   * on the origin the data was released for. Identity fields that already
   * hold a value are left alone. Returns the number of fields filled.
   */
  function fillForm(expectedOrigin, kind, data) {
    if (location.origin !== expectedOrigin || window !== window.top) return 0;
    let n = 0;
    for (const [el, token] of fields(kind)) {
      if (kind === "identity" && el.value) continue;
      const values = valuesFor(token, kind, data, {
        maxLength: el.maxLength,
        placeholder: el.getAttribute("placeholder"),
        multiline: el.tagName === "TEXTAREA",
      }).filter((v) => v !== undefined && v !== null && v !== "");
      if (!values.length) continue;
      if (el.tagName === "SELECT") {
        const want = values.map((v) => String(v).toLowerCase());
        const opt = [...el.options].find((o) => want.includes(o.value.toLowerCase()) || want.includes(o.text.trim().toLowerCase()));
        if (!opt) continue;
        set(el, opt.value);
      } else {
        set(el, String(values[0]));
      }
      n++;
    }
    return n;
  }

  globalThis.__secretVault = { classifyField, valuesFor, detect, fillForm };
})();
