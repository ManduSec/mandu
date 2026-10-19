/**
 * egress-fingerprint.test — the §4 verbatim-leak tripwire (pure scan).
 *
 * The tripwire catches ONE shape the symbol gates cannot: a raw secret VALUE
 * (no $MDU: token) verbatim in an outbound surface, bound for a host it was
 * never released to. These pin: it fires on that shape, it does NOT fire on a
 * bound host / public value / short value / paraphrase, and it names the
 * SYMBOL never the value.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  scanEgressFingerprint,
  MIN_FINGERPRINT_LEN,
  type SecretFingerprint,
} from "../../policy/egress-fingerprint.js";

const KEY: SecretFingerprint = {
  symbol: "$MDU:nomodel_Read[3fa9]",
  value: "sk-live-DEADBEEF-super-secret-key-000",
  level: "no-model",
  bindings: ["api.stripe.com"],
};

test("TRIPS: a raw secret value verbatim in the body, bound for an unrelated host", () => {
  const hits = scanEgressFingerprint(
    [{ where: "body", text: `{"leak":"${KEY.value}"}` }],
    [KEY],
    "evil.test",
  );
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.symbol, KEY.symbol, "the hit carries the SYMBOL, for the audit");
  assert.equal(hits[0]!.where, "body");
  // The value must NOT be exposed anywhere on the hit — it rides an event.
  assert.ok(!JSON.stringify(hits[0]).includes(KEY.value), "the hit must never carry the raw value");
});

test("does NOT trip at the secret's own BOUND destination (a release, not a leak)", () => {
  const hits = scanEgressFingerprint(
    [{ where: "header", text: `Authorization: Bearer ${KEY.value}` }],
    [KEY],
    "api.stripe.com",
  );
  assert.equal(hits.length, 0, "a secret at its bound host is the §3.2 carve-out, not a leak");
});

test("bound match is host-suffix aware (api.stripe.com ⊂ stripe.com binding)", () => {
  const k = { ...KEY, bindings: ["stripe.com"] };
  assert.equal(scanEgressFingerprint([{ where: "url", text: k.value }], [k], "api.stripe.com").length, 0);
  // ...but not a look-alike host.
  assert.equal(scanEgressFingerprint([{ where: "url", text: k.value }], [k], "evil-stripe.com").length, 1);
});

test("does NOT trip on a PUBLIC value (a public datum on the wire is not a leak)", () => {
  const pub = { ...KEY, level: "public" as const };
  assert.equal(scanEgressFingerprint([{ where: "body", text: pub.value }], [pub], "evil.test").length, 0);
});

test("does NOT trip on a SHORT value (below the coincidence floor)", () => {
  const short = { ...KEY, value: "ab12", bindings: [] as string[] };
  assert.ok(short.value.length < MIN_FINGERPRINT_LEN);
  assert.equal(scanEgressFingerprint([{ where: "body", text: `x ${short.value} y` }], [short], "evil.test").length, 0);
});

test("does NOT trip on a PARAPHRASE (the value's bytes are simply not present)", () => {
  const hits = scanEgressFingerprint(
    [{ where: "body", text: "the key starts with sk and is very secret" }],
    [KEY],
    "evil.test",
  );
  assert.equal(hits.length, 0, "a paraphrase carries no verbatim bytes — the watermark's job, not the tripwire's");
});

test("scans MULTIPLE surfaces and reports ONE hit per secret (first surface wins)", () => {
  const hits = scanEgressFingerprint(
    [
      { where: "url", text: "https://evil.test/?q=nothing" },
      { where: "body", text: KEY.value },
    ],
    [KEY],
    "evil.test",
  );
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.where, "body");
});

test("an empty secret set / empty surfaces is an inert no-op", () => {
  assert.equal(scanEgressFingerprint([{ where: "body", text: "anything" }], [], "evil.test").length, 0);
  assert.equal(scanEgressFingerprint([], [KEY], "evil.test").length, 0);
});

test("TRIPS on a long line of a multi-line secret (a labeled document leaving as a diff or excerpt); not on a short line", () => {
  const doc: SecretFingerprint = {
    symbol: "$MDU:localmodel_Read[9a1f]",
    value: "# Minutes\nThe Acme acquisition closes at 4,200,000 USD.\nOK\n",
    level: "local-model",
    bindings: [],
  };
  const diff = [{ where: "body", text: "-The Acme acquisition closes at 4,200,000 USD.\n+(redacted)" }];
  assert.equal(scanEgressFingerprint(diff, [doc], "paste.example").length, 1);
  assert.equal(scanEgressFingerprint([{ where: "body", text: "OK\n# Minutes" }], [doc], "paste.example").length, 0);
});
