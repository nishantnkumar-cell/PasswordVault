import { test } from "node:test";
import assert from "node:assert/strict";
import { crossOriginFrames, fillableFrames, framesWithOrigin, fromPopup, originOf } from "../lib/policy.js";

test("originOf accepts only http(s)", () => {
  assert.equal(originOf("https://Example.com:443/login?x=1"), "https://example.com");
  assert.equal(originOf("http://example.com:8080/"), "http://example.com:8080");
  assert.equal(originOf("chrome://settings"), null);
  assert.equal(originOf("file:///etc/passwd"), null);
  assert.equal(originOf("javascript:alert(1)"), null);
  assert.equal(originOf("not a url"), null);
});

test("only top and same-origin frames are fillable", () => {
  const frames = [
    { frameId: 0, url: "https://bank.example/login" },
    { frameId: 3, url: "https://bank.example/widget" },
    { frameId: 4, url: "https://ads.evil.test/frame" },
    { frameId: 5, url: "about:blank" },
    { frameId: 6, url: "https://sub.bank.example/" },
  ];
  assert.deepEqual(fillableFrames(frames, "https://bank.example"), [0, 3]);
});

test("messages are accepted only from the popup", () => {
  const popup = "chrome-extension://abc/popup.html";
  assert.ok(fromPopup({ id: "abc", url: popup }, "abc", popup));
  assert.ok(!fromPopup({ id: "abc", url: "https://x.test/", tab: { id: 1 } }, "abc", popup));
  assert.ok(!fromPopup({ id: "other", url: popup }, "abc", popup));
});

test("cross-origin https frames are offered, never filled by default", () => {
  const frames = [
    { frameId: 0, url: "https://shop.example/checkout" },
    { frameId: 2, url: "https://login.idp.example/widget" },
    { frameId: 3, url: "https://login.idp.example/other" },
    { frameId: 4, url: "http://plain.example/" },
    { frameId: 5, url: "https://shop.example/same" },
  ];
  assert.deepEqual(crossOriginFrames(frames, "https://shop.example"), ["https://login.idp.example"]);
  assert.deepEqual(framesWithOrigin(frames, "https://login.idp.example"), [2, 3]);
  assert.deepEqual(framesWithOrigin(frames, "https://shop.example"), [5]);
});
