import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

// The injected script is a classic script; run it in a fresh context.
const ctx = vm.createContext({});
vm.runInContext(readFileSync(new URL("../lib/form-inject.js", import.meta.url), "utf8"), ctx);
const { classifyField, valuesFor } = ctx.__secretVault;

test("autocomplete attributes win", () => {
  assert.equal(classifyField({ autocomplete: "cc-number", name: "email" }), "cc-number");
  assert.equal(classifyField({ autocomplete: "section-pay billing cc-exp" }), "cc-exp");
  assert.equal(classifyField({ autocomplete: "shipping postal-code" }), "postal-code");
  assert.equal(classifyField({ autocomplete: "cc-given-name" }), "cc-name");
  // "off" says nothing about the field, so guessing continues.
  assert.equal(classifyField({ autocomplete: "off", name: "cardnumber" }), "cc-number");
});

test("fields are guessed from their names and labels", () => {
  const c = (f) => classifyField(f);
  assert.equal(c({ name: "card_number" }), "cc-number");
  assert.equal(c({ label: "Name on card" }), "cc-name");
  assert.equal(c({ id: "cvc" }), "cc-csc");
  assert.equal(c({ name: "exp_month" }), "cc-exp-month");
  assert.equal(c({ name: "exp_year" }), "cc-exp-year");
  assert.equal(c({ placeholder: "MM / YY" }), "cc-exp");
  assert.equal(c({ type: "email", name: "x" }), "email");
  assert.equal(c({ label: "Email address" }), "email");
  assert.equal(c({ name: "firstName" }), "given-name");
  assert.equal(c({ name: "lastname" }), "family-name");
  assert.equal(c({ label: "Street address" }), "address-line1");
  assert.equal(c({ name: "address2" }), "address-line2");
  assert.equal(c({ name: "zip" }), "postal-code");
  assert.equal(c({ label: "Town / City" }), "address-level2");
  assert.equal(c({ label: "County" }), "address-level1");
  assert.equal(c({ name: "country" }), "country");
  assert.equal(c({ type: "password", name: "card_number" }), null);
  assert.equal(c({ name: "search" }), null);
});

const card = { holder: "A Person", number: "4111111111111111", expMonth: 7, expYear: 2031, cvv: "123", brand: "Visa" };

test("card values follow the field's shape", () => {
  assert.deepEqual([...valuesFor("cc-number", "card", card)], ["4111111111111111"]);
  assert.deepEqual([...valuesFor("cc-exp", "card", card)], ["07/31"]);
  assert.deepEqual([...valuesFor("cc-exp", "card", card, { placeholder: "MM / YYYY" })], ["07 / 2031"]);
  assert.deepEqual([...valuesFor("cc-exp", "card", card, { maxLength: 7 })], ["07/2031"]);
  assert.equal(valuesFor("cc-exp-year", "card", card)[0], "2031");
  assert.equal(valuesFor("cc-exp-year", "card", card, { maxLength: 2 })[0], "31");
  // Month selects may use numbers or names.
  assert.deepEqual([...valuesFor("cc-exp-month", "card", card)], ["07", "7", "July", "Jul"]);
  assert.deepEqual([...valuesFor("cc-exp", "card", { ...card, expMonth: 0 })], []);
});

test("identity values", () => {
  const id = { fullName: "Ada Lovelace", givenName: "Ada", address1: "1 Main St", address2: "Flat 2", postcode: "N1" };
  assert.equal(valuesFor("name", "identity", id)[0], "Ada Lovelace");
  assert.equal(valuesFor("street-address", "identity", id)[0], "1 Main St, Flat 2");
  assert.equal(valuesFor("street-address", "identity", id, { multiline: true })[0], "1 Main St\nFlat 2");
  assert.equal(valuesFor("postal-code", "identity", id)[0], "N1");
  // A card token never takes identity data, and the reverse.
  assert.deepEqual([...valuesFor("cc-number", "identity", id)], []);
  assert.deepEqual([...valuesFor("email", "card", card)], []);
});
