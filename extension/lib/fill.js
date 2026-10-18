// Injected into the page with chrome.scripting.executeScript, so this
// function must be self-contained: no imports, no outer variables.

/**
 * Fill the first visible login form. Returns the number of fields filled.
 * Refuses if the frame's origin is not the one the item was released for
 * (the page may have navigated since the popup asked).
 */
export function fillInPage(expectedOrigin, username, password) {
  if (location.origin !== expectedOrigin) return 0;

  const visible = (el) => {
    if (el.disabled || el.readOnly || el.type === "hidden") return false;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
      const s = getComputedStyle(n);
      if (s.display === "none" || s.visibility === "hidden" || s.visibility === "collapse" || Number(s.opacity) < 0.1) return false;
    }
    return r.bottom > 0 && r.right > 0 && r.left < innerWidth + scrollX && r.top < document.documentElement.scrollHeight;
  };
  const set = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const pw = [...document.querySelectorAll("input[type=password]")].find(visible);
  if (!pw) return 0;
  const scope = pw.form || document;
  const candidates = [...scope.querySelectorAll("input")].filter(
    (el) => visible(el) && ["text", "email", "tel", ""].includes(el.getAttribute("type") ?? "") && el.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING,
  );
  let filled = 0;
  const user = candidates.at(-1);
  if (user && username) {
    set(user, username);
    filled++;
  }
  set(pw, password);
  return filled + 1;
}
