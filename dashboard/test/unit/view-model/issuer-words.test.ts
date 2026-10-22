/**
 * issuer-words.test — Rules › Built-in protections' issuer item
 * (dashboard.md §4.25z, confidentiality.md §2.3): `issuerState` reads
 * policy.yaml's `issuer_bindings` as the arbiter compiles it (absent on,
 * `false` off, a mapping on but for its exceptions, anything malformed
 * off), and the item's words say each state, never "on" for a state not
 * read. The copy's parity with the arbiter is tests/stack/issuer-table-parity.
 * `issuerOfHost` (the session page's sent step, §4.25b) names a company only
 * for one of its exact hosts while its keys go there without asking.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { ISSUER_TABLE, issuerItem, issuerOfHost, issuerState } from "../../../src/view-model/issuer-words.js";

const ON = { enabled: true, issuersOff: [], valuesOff: [] };
const OFF = { enabled: false, issuersOff: [], valuesOff: [] };
const SENT = "A key whose format names the company that issued it goes to that company's own API without asking.";
const codes = (parts: Array<{ kind: string; text: string }>) => parts.filter((p) => p.kind === "code").map((p) => p.text);

test("issuerState: absent and true are on, false is off, a mapping is on but for its exceptions", () => {
  assert.deepEqual(issuerState(undefined), ON);
  assert.deepEqual(issuerState(null), ON);
  assert.deepEqual(issuerState(true), ON);
  assert.deepEqual(issuerState(false), OFF);
  assert.deepEqual(issuerState({}), ON);
  assert.deepEqual(issuerState({ issuers_off: ["stripe"] }), { enabled: true, issuersOff: ["stripe"], valuesOff: [] });
  assert.deepEqual(issuerState({ values_off: ["PROD_*", "STRIPE_LIVE_KEY", "PROD_*"] }), { enabled: true, issuersOff: [], valuesOff: ["PROD_*", "STRIPE_LIVE_KEY"] });
  assert.deepEqual(issuerState({ issuers_off: ["github", "github"], values_off: ["X"] }), { enabled: true, issuersOff: ["github"], valuesOff: ["X"] });
});

test("issuerState: anything malformed reads as OFF, as the arbiter compiles it", () => {
  for (const bad of [
    "yes", 1, [], ["stripe"],
    { issuers_off: "stripe" }, { issuers_off: ["stripe", "acme"] }, { issuers_off: [1] }, { issuers_off: null },
    { values_off: "PROD_*" }, { values_off: ["has space"] }, { values_off: [""] }, { values_off: ["x".repeat(257)] },
    { other: true }, { issuers_off: [], typo: 1 },
  ]) {
    assert.deepEqual(issuerState(bad), OFF, JSON.stringify(bad));
  }
});

test("the item, on: the sentence, each company with its hosts, and the policy.yaml text that changes it", () => {
  const it = issuerItem({ read: true, raw: undefined });
  assert.equal(it.state, "on");
  assert.equal(it.text, SENT);
  assert.equal(it.companies.length, ISSUER_TABLE.length);
  assert.deepEqual(it.companies[0], { name: "Stripe", hosts: ["api.stripe.com", "files.stripe.com"], off: false });
  assert.ok(it.companies.every((c) => !c.off && c.hosts.length > 0));
  assert.deepEqual(codes(it.change!.parts), ["issuer_bindings: false", "policy.yaml", "issuer_bindings: { issuers_off: [stripe] }"]);
  assert.equal(it.change!.text, it.change!.parts.map((p) => p.text).join(""));
  assert.deepEqual(issuerItem({ read: true, raw: true }), it);
});

test("the item, partly: it names the companies and the values that still ask", () => {
  const stripe = issuerItem({ read: true, raw: { issuers_off: ["stripe"] } });
  assert.equal(stripe.state, "partly");
  assert.equal(stripe.text, `${SENT} Off for: Stripe.`);
  assert.equal(stripe.companies.find((c) => c.name === "Stripe")!.off, true);
  assert.equal(stripe.companies.filter((c) => c.off).length, 1);
  const both = issuerItem({ read: true, raw: { issuers_off: ["github", "stripe"], values_off: ["PROD_*"] } });
  assert.equal(both.text, `${SENT} Off for: Stripe, GitHub; and for PROD_*.`, "in the table's order");
  assert.deepEqual(codes(both.parts), ["PROD_*"], "a value name is code");
  const values = issuerItem({ read: true, raw: { values_off: ["PROD_*", "STAGING_KEY"] } });
  assert.equal(values.text, `${SENT} Off for: PROD_*, STAGING_KEY.`);
  assert.ok(values.companies.every((c) => !c.off));
});

test("the item, off: every key asks, says why, and how to turn it back on; no company list", () => {
  const off = issuerItem({ read: true, raw: false });
  assert.equal(off.state, "off");
  assert.equal(off.text, "Every key asks before it goes to its company's API (issuer_bindings is off in policy.yaml).");
  assert.deepEqual(codes(off.parts), ["issuer_bindings", "policy.yaml"]);
  assert.deepEqual(off.companies, []);
  assert.equal(off.change!.text, "To turn it back on, remove issuer_bindings from policy.yaml.");
  const bad = issuerItem({ read: true, raw: { issuers_off: ["acme"] } });
  assert.equal(bad.state, "off");
  assert.equal(bad.text, "Every key asks before it goes to its company's API (the issuer_bindings setting in policy.yaml is not valid, so it is off).");
});

test("the item, not read: it says Mandu could not read it, and never claims on or off", () => {
  for (const reading of [undefined, { read: false } as const]) {
    const it = issuerItem(reading);
    assert.equal(it.state, "unknown");
    assert.equal(it.text, "Mandu could not read whether a key whose format names the company that issued it goes to that company's own API without asking.");
    assert.deepEqual(it.companies, []);
    assert.equal(it.change, null);
    assert.doesNotMatch(it.text, /^A key|asks before/);
  }
});

test("issuerOfHost: the company of an exact host while its keys go without asking; null for anything else", () => {
  const on = { read: true, raw: undefined } as const;
  assert.equal(issuerOfHost("api.github.com", on)?.name, "GitHub");
  assert.equal(issuerOfHost("uploads.github.com", { read: true, raw: true })?.id, "github");
  assert.equal(issuerOfHost("API.Stripe.com:443", on)?.name, "Stripe", "case and :443 aside");
  assert.equal(issuerOfHost("api.stripe.com.", on)?.name, "Stripe", "a trailing dot aside");
  for (const host of ["x.api.github.com", "github.com", "api.github.com.evil.io", "api-github.com", "api.github.com:8443", "paste.example", ""]) {
    assert.equal(issuerOfHost(host, on), null, host);
  }
  // The company off, the switch off or malformed, the switch not read.
  assert.equal(issuerOfHost("api.github.com", { read: true, raw: { issuers_off: ["github"] } }), null, "issuers_off");
  assert.equal(issuerOfHost("api.stripe.com", { read: true, raw: { issuers_off: ["github"] } })?.name, "Stripe", "only the company off");
  assert.equal(issuerOfHost("api.github.com", { read: true, raw: { values_off: ["GH_*"] } })?.name, "GitHub", "values_off: other keys still go");
  assert.equal(issuerOfHost("api.github.com", { read: true, raw: false }), null, "the switch off");
  assert.equal(issuerOfHost("api.github.com", { read: true, raw: { issuers_off: ["acme"] } }), null, "malformed reads as off");
  assert.equal(issuerOfHost("api.github.com", { read: false }), null, "not read");
  assert.equal(issuerOfHost("api.github.com", undefined), null, "no reading");
});
