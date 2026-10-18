// Pure decisions for the background script, kept free of browser APIs so
// they can be tested with `node --test`.

/** The page origin, from a URL the browser reported. Only http(s) pages are fillable. */
export function originOf(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  return u.origin;
}

/**
 * Frames to fill: the top frame, plus child frames whose own URL has the same
 * origin as the top frame. Cross-origin frames are never filled, and neither
 * are about:blank or srcdoc frames, whose origin the URL does not show.
 */
export function fillableFrames(frames, topOrigin) {
  return frames
    .filter((f) => f.frameId === 0 || originOf(f.url) === topOrigin)
    .map((f) => f.frameId);
}

/** Only messages from this extension's own popup are accepted. */
export function fromPopup(sender, runtimeId, popupUrl) {
  return sender.id === runtimeId && typeof sender.url === "string" && sender.url.startsWith(popupUrl) && !sender.tab;
}

/**
 * Origins of https child frames that are not the top frame's origin. These
 * are never filled without the user confirming that frame's origin.
 */
export function crossOriginFrames(frames, topOrigin) {
  const out = new Set();
  for (const f of frames) {
    const o = originOf(f.url);
    if (f.frameId !== 0 && o && o !== topOrigin && o.startsWith("https:")) out.add(o);
  }
  return [...out];
}

/** Frame IDs whose own URL has exactly `origin`. */
export function framesWithOrigin(frames, origin) {
  return frames.filter((f) => f.frameId !== 0 && originOf(f.url) === origin).map((f) => f.frameId);
}
