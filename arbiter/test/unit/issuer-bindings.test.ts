/**
 * issuer-bindings — the default catalog's issuer table and its matching
 * (confidentiality.md §2.3): a key whose format names its issuer, at that
 * issuer's EXACT API host, HTTPS, in the Authorization header only; every
 * lookalike host, path, port, scheme or position misses; the policy.yaml
 * switch validates, compiles (fail-closed to off) and counts as a
 * relaxation when it lets more go.
 *
 * Pure. Mandu-new test. Axes stated: `secrets` (the release is the
 * confidentiality axis's).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_ISSUER_BINDINGS, ISSUERS, checkIssuerBindings, compileIssuerBindings, isIssuerHost, issuerDestinationHost,
  issuerOfHost, issuerOfValue, issuerRelease, type IssuerBindingSettings,
} from "../../policy/issuer-bindings.js";
import { compilePolicy } from "../../policy/compiled-policy.js";
import { policyDelta } from "../../policy/policy-delta.js";
import { validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { NO_ADMIN_LAYER } from "../../policy/admin-layer.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { isAgentCredentialPath } from "../../secret-registry/current-bindings.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const alnum = (n: number, seed = 7): string => {
  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let x = seed, out = "";
  while (out.length < n) { x = (Math.imul(x, 1103515245) + 12345) >>> 0; out += abc[(x >>> 16) % abc.length]; }
  return out;
};

/** One real-shaped key per issuer (built here, never written out whole). */
const KEY: Record<string, string> = {
  stripe: ["sk", "live", `51${alnum(97)}`].join("_"),
  github: ["ghp", alnum(36)].join("_"),
  notion: ["ntn", `11235813213${alnum(35)}`].join("_"),
  openai: ["sk", "proj", alnum(48)].join("-"),
  slack: ["xoxb", "1234567890", "1234567890123", alnum(24)].join("-"),
  npm: ["npm", alnum(36)].join("_"),
  pypi: `pypi-AgEIcHlwaS5vcmc${alnum(120)}`,
  huggingface: ["hf", alnum(34)].join("_"),
  sendgrid: `SG.${alnum(22)}.${alnum(43)}`,
};
const HEADER = { scheme: "https", positions: ["authorization"] } as const;
const ON: IssuerBindingSettings = DEFAULT_ISSUER_BINDINGS;

test("every issuer: its sample key names it, its hosts release, and its row cites the issuer's own docs", () => {
  assert.deepEqual(ISSUERS.map((i) => i.id).sort(), Object.keys(KEY).sort());
  for (const i of ISSUERS) {
    assert.equal(issuerOfValue(KEY[i.id]!)?.id, i.id, i.id);
    assert.ok(i.hosts.length > 0 && i.docs.length > 0, i.id);
    for (const d of i.docs) assert.match(d, /^https:\/\//, `${i.id}: ${d}`);
    for (const h of i.hosts) {
      assert.equal(h, h.toLowerCase(), h);
      assert.equal(issuerOfHost(h)?.id, i.id, h);
      const r = issuerRelease({ value: KEY[i.id]!, names: ["K"], destination: h, ...HEADER }, ON);
      assert.ok("issuer" in r && r.issuer.id === i.id, `${i.id} at ${h}: ${JSON.stringify(r)}`);
    }
  }
  // no host belongs to two issuers
  const all = ISSUERS.flatMap((i) => i.hosts);
  assert.equal(new Set(all).size, all.length);
});

test("a key goes to its OWN issuer only: another issuer's host misses", () => {
  for (const i of ISSUERS) for (const j of ISSUERS) {
    if (i.id === j.id) continue;
    const r = issuerRelease({ value: KEY[i.id]!, names: ["K"], destination: j.hosts[0]!, ...HEADER }, ON);
    assert.deepEqual(r, { miss: "host" }, `${i.id} key at ${j.hosts[0]}`);
  }
});

test("lookalike hosts never match: suffixes, prefixes, subdomains, the parent, addresses, ports, schemes, userinfo", () => {
  const stripe = ISSUERS.find((i) => i.id === "stripe")!;
  const miss = [
    "api.stripe.com.evil.io", "api-stripe.com", "stripe.com", "x.api.stripe.com", "evilapi.stripe.com",
    "api.stripe.co", "api.stripe.com.", "api.stripe.com:8443", "api.stripe.com:80", "http://api.stripe.com/v1",
    "https://user@api.stripe.com/", "https://api.stripe.com@evil.io/", "*.stripe.com", "54.187.216.72", "[::1]",
    "api.stripe.com/v1/charges", "", "api.stripe.com:443:1", "apı.stripe.com",
  ];
  for (const d of miss) {
    if (d === "api.stripe.com.") continue; // a trailing dot is the same name (below)
    assert.equal(isIssuerHost(stripe, d), false, d);
    const r = issuerRelease({ value: KEY.stripe!, names: ["K"], destination: d, ...HEADER }, ON);
    assert.deepEqual(r, { miss: "host" }, d);
  }
  for (const d of ["api.stripe.com", "API.Stripe.COM", "api.stripe.com.", "api.stripe.com:443", "https://api.stripe.com/v1/charges?limit=3", "https://api.stripe.com:443/"]) {
    assert.equal(isIssuerHost(stripe, d), true, d);
  }
  assert.equal(issuerDestinationHost("api.stripe.com.evil.io"), "api.stripe.com.evil.io");
  assert.equal(issuerOfHost("api.stripe.com.evil.io"), null);
  assert.equal(issuerOfHost("stripe.com"), null);
});

test("lookalike values never name an issuer: a prefix alone, a short or odd body, a stand-in, another vendor's key", () => {
  const no = [
    "sk_live_", "sk_live_short", `sk_live_${alnum(10)}`, `sk_live_${alnum(20)}_x`, `pk_live_${alnum(40)}`, `sk_prod_${alnum(40)}`,
    `xsk_live_${alnum(40)}`, ` sk_live_${alnum(40)}`, `sk_live_${alnum(40)}\n`, `Bearer sk_live_${alnum(40)}`,
    `sk-ant-api03-${alnum(80)}`, `sk-${alnum(48)}`, `ghr_${alnum(36)}`, `glpat-${alnum(20)}`, `secret_${alnum(43)}`,
    `AKIA${alnum(16).toUpperCase()}`, `hf_${alnum(20)}`, `npm_${alnum(30)}`, `SG.${alnum(22)}`, `xoxa-${alnum(40)}`,
    "sk_live_$MDU:nomodel_Read[abcd].KEY", "", "x".repeat(5000),
  ];
  for (const v of no) assert.equal(issuerOfValue(v), null, JSON.stringify(v.slice(0, 40)));
  assert.equal(issuerOfValue(42), null);
  assert.equal(issuerOfValue(null), null);
});

test("HTTPS and the Authorization header only; a probe answers for that send", () => {
  const base = { value: KEY.stripe!, names: ["STRIPE_SECRET_KEY"], destination: "api.stripe.com" };
  assert.deepEqual(issuerRelease({ ...base, scheme: "http", positions: ["authorization"] }, ON), { miss: "scheme" });
  assert.deepEqual(issuerRelease({ ...base, positions: ["authorization"] }, ON), { miss: "scheme" }, "a scheme not stated is not https");
  for (const positions of [["body"], ["url"], ["header"], ["authorization", "body"], [], undefined, ["Authorization"], "authorization"]) {
    assert.deepEqual(issuerRelease({ ...base, scheme: "https", positions }, ON), { miss: "position" }, JSON.stringify(positions));
  }
  assert.ok("issuer" in issuerRelease({ ...base, ...HEADER }, ON));
  assert.ok("issuer" in issuerRelease({ ...base, probe: true }, ON), "a probe states no request");
  assert.deepEqual(issuerRelease({ ...base, destination: "api-stripe.com", probe: true }, ON), { miss: "host" });
});

test("the switch: off globally, per issuer, per value name (globs as values: keys)", () => {
  const base = { value: KEY.stripe!, names: ["STRIPE_SECRET_KEY"], destination: "api.stripe.com", ...HEADER };
  assert.deepEqual(issuerRelease(base, compileIssuerBindings(false)), { miss: "off" });
  assert.ok("issuer" in issuerRelease(base, compileIssuerBindings(true)));
  assert.ok("issuer" in issuerRelease(base, compileIssuerBindings(undefined)));
  assert.deepEqual(issuerRelease(base, compileIssuerBindings({ issuers_off: ["stripe"] })), { miss: "issuer-off" });
  assert.ok("issuer" in issuerRelease(base, compileIssuerBindings({ issuers_off: ["github"] })));
  assert.deepEqual(issuerRelease(base, compileIssuerBindings({ values_off: ["STRIPE_*"] })), { miss: "value-off" });
  assert.deepEqual(issuerRelease(base, compileIssuerBindings({ values_off: ["STRIPE_SECRET_KEY"] })), { miss: "value-off" });
  assert.ok("issuer" in issuerRelease(base, compileIssuerBindings({ values_off: ["OTHER_KEY"] })));
  // malformed compiles to OFF (fail-closed), and the validator names it
  for (const bad of ["yes", 1, [], { issuers_off: ["stripe", "nope"] }, { values_off: "X" }, { off: [] }, { values_off: ["A B"] }]) {
    assert.equal(compileIssuerBindings(bad).enabled, false, JSON.stringify(bad));
    const out: string[] = [];
    checkIssuerBindings(bad, "issuer_bindings", out);
    assert.ok(out.length > 0, JSON.stringify(bad));
  }
  const ok: string[] = [];
  checkIssuerBindings({ issuers_off: ["stripe", "npm"], values_off: ["PROD_*"] }, "issuer_bindings", ok);
  assert.deepEqual(ok, []);
});

test("policy.yaml: the key validates, compiles, and turning it on or shortening an off-list is a relaxation", () => {
  assert.deepEqual(validatePolicyDocument({ version: 1, issuer_bindings: false }, NO_ADMIN_LAYER), []);
  assert.deepEqual(validatePolicyDocument({ version: 1, issuer_bindings: { issuers_off: ["slack"] } }, NO_ADMIN_LAYER), []);
  assert.ok(validatePolicyDocument({ version: 1, issuer_bindings: { issuers_off: ["acme"] } }, NO_ADMIN_LAYER).some((p) => /issuers_off\[0\]/.test(p)));
  const law = (doc: Record<string, unknown> | null) => compilePolicy({ specId: "claude-code", document: doc ? ({ version: 1, ...doc } as PolicyFileConfig) : null });
  assert.equal(law(null).issuerBindings.enabled, true, "a fresh install has it on");
  assert.equal(law({ issuer_bindings: false }).issuerBindings.enabled, false);
  const on = law({});
  const off = law({ issuer_bindings: false });
  const someOff = law({ issuer_bindings: { issuers_off: ["stripe"], values_off: ["PROD_*"] } });
  assert.deepEqual(policyDelta(off, on).relaxations.map((r) => r.subject), ["issuer_bindings"]);
  assert.deepEqual(policyDelta(on, off).relaxations, []);
  assert.deepEqual(policyDelta(on, off).tightenings.map((r) => r.subject), ["issuer_bindings"]);
  assert.deepEqual(policyDelta(someOff, on).relaxations.map((r) => r.subject).sort(), ["issuer_bindings.issuers_off:stripe", "issuer_bindings.values_off:PROD_*"]);
  assert.deepEqual(policyDelta(on, someOff).relaxations, []);
});

test("an AI agent's own login or key file never uses an issuer binding (its auth grant ends with the launch)", () => {
  for (const p of [
    "/h/.config/goose/secrets.yaml", "/h/.codex/auth.json", "/x/codex-home/auth.json", "/h/.local/share/opencode/auth.json",
    "/h/.claude/.credentials.json", "/h/.claude.json", "/cfg/.credentials.json", "/h/.anthropic/key", "/h/.openai",
  ]) assert.equal(isAgentCredentialPath(p), true, p);
  for (const p of ["/h/proj/.env", "/h/.config/stripe/config.toml", "/h/proj/secrets.yaml", "/h/proj/author.json", "/h/.openai-notes.md"]) {
    assert.equal(isAgentCredentialPath(p), false, p);
  }
});
