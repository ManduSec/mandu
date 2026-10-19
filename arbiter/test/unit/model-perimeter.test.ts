/**
 * model-perimeter.test — policy.yaml `perimeter:` (confidentiality plan 12
 * D4): the section's syntax, the load refusal for a literal address outside
 * it, how it compiles onto the endpoints it applies to (a `local: true` entry
 * on another machine; `orgDomain` for a name under `domains`), and the delta:
 * dropping or widening the networks is a relaxation, adding or narrowing a
 * tightening, `domains` changes nothing the law means.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { cidrWithin, compilePerimeter, inPerimeter, networksWithin, parseCidr } from "../../policy/model-perimeter.js";
import { validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { compilePolicy } from "../../policy/compiled-policy.js";
import { policyDelta } from "../../policy/policy-delta.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // local-model is a confidentiality level; the perimeter reads no axis

const corp = { name: "corp", url: "https://llm.corp.example/v1", wire: "openai-chat" as const, model: "qwen", local: true };

test("parseCidr / inPerimeter / cidrWithin: both families, a bare address is one host, mapped IPv4 unwrapped", () => {
  assert.deepEqual(parseCidr("10.0.0.0/8"), { address: "10.0.0.0", prefix: 8, family: "ipv4" });
  assert.deepEqual(parseCidr("fd00:1234::/32"), { address: "fd00:1234::", prefix: 32, family: "ipv6" });
  assert.deepEqual(parseCidr("192.0.2.7"), { address: "192.0.2.7", prefix: 32, family: "ipv4" });
  for (const bad of ["10.0.0.0/33", "fd00::/129", "corp.example", "10.0.0/8", "", "10.0.0.0/-1", 8]) assert.equal(parseCidr(bad), null, String(bad));
  assert.ok(inPerimeter("10.9.8.7", ["10.0.0.0/8"]));
  assert.ok(inPerimeter("::ffff:10.9.8.7", ["10.0.0.0/8"]));
  assert.ok(!inPerimeter("172.32.0.1", ["172.16.0.0/12"]));
  assert.ok(cidrWithin("10.1.0.0/16", "10.0.0.0/8") && !cidrWithin("10.0.0.0/8", "10.1.0.0/16") && !cidrWithin("fd00::/8", "10.0.0.0/8"));
  assert.ok(networksWithin(["10.1.0.0/16", "10.2.3.4"], ["10.0.0.0/8"]) && !networksWithin(["10.1.0.0/16", "192.168.0.0/16"], ["10.0.0.0/8"]));
});

test("validate: networks and domains shapes; unknown keys, an empty list, a malformed network or domain refused", () => {
  assert.deepEqual(validatePolicyDocument({ perimeter: { networks: ["10.0.0.0/8", "fd00:1234::/32"], domains: ["corp.example", ".lab.example"] } }), []);
  assert.deepEqual(validatePolicyDocument({ perimeter: { domains: ["corp.example"] } }), []);
  const p = (perimeter: unknown) => validatePolicyDocument({ perimeter }).join("\n");
  assert.match(p({}), /perimeter: needs 'networks' and\/or 'domains'/);
  assert.match(p({ networks: [] }), /perimeter\.networks: must be a non-empty list/);
  assert.match(p({ networks: ["10.0.0.0/33"] }), /perimeter\.networks\[0\]: not a network: "10\.0\.0\.0\/33"/);
  assert.match(p({ domains: ["not a name"] }), /perimeter\.domains\[0\]: not a domain name/);
  assert.match(p({ networks: ["10.0.0.0/8"], cidrs: [] }), /perimeter\.cidrs: unknown key/);
  assert.match(p(["10.0.0.0/8"]), /perimeter: must be a mapping/);
});

test("validate: a local entry at a literal address outside the networks is refused at load; inside, a name, an outside model or no networks pass", () => {
  const doc = (url: string, extra: Record<string, unknown> = {}) => ({ perimeter: { networks: ["10.0.0.0/8"] }, models: [{ ...corp, url, ...extra }] });
  assert.match(validatePolicyDocument(doc("https://203.0.113.9:8443")).join("\n"),
    /models\[0\]\.url: 'corp' is at 203\.0\.113\.9, outside perimeter\.networks \(10\.0\.0\.0\/8\); fix the address or list its network/);
  assert.match(validatePolicyDocument(doc("https://[2001:db8::1]:8443")).join("\n"), /is at 2001:db8::1, outside/);
  assert.deepEqual(validatePolicyDocument(doc("https://10.2.3.4:8443")), []);
  assert.deepEqual(validatePolicyDocument(doc("https://drift.corp.example")), [], "a name is checked where it is dialed");
  assert.deepEqual(validatePolicyDocument(doc("https://203.0.113.9:8443", { local: false })), []);
  assert.deepEqual(validatePolicyDocument(doc("http://127.0.0.1:11434")), [], "this computer is not held to the perimeter");
  assert.deepEqual(validatePolicyDocument({ perimeter: { domains: ["corp.example"] }, models: [{ ...corp, url: "https://203.0.113.9" }] }), []);
});

test("compile: the networks ride each local entry on another machine; orgDomain marks a network name under domains; the section itself is kept", () => {
  const doc: PolicyFileConfig = {
    perimeter: { networks: ["10.0.0.0/8"], domains: ["Corp.Example."] },
    models: [
      corp,
      { name: "home", url: "http://127.0.0.1:11434", local: true },
      { name: "outside", url: "https://api.corp.example", local: false },
      { name: "lab", url: "https://10.3.3.3:8443", local: true },
    ],
  };
  const c = compilePolicy({ specId: "claude-code", document: doc });
  assert.deepEqual(c.perimeter, { networks: ["10.0.0.0/8"], domains: ["corp.example"] });
  const by = Object.fromEntries(c.models.map((m) => [m.name, [m.perimeter ?? null, m.orgDomain ?? false]]));
  assert.deepEqual(by, {
    corp: [["10.0.0.0/8"], true],
    home: [null, false],
    outside: [null, true],
    lab: [["10.0.0.0/8"], false],
  });
  assert.equal(compilePolicy({ specId: "claude-code", document: { models: [corp] } }).models[0]!.perimeter, undefined, "no section, no field");
  assert.equal(compilePerimeter({ domains: ["corp.example"] })?.networks, null, "domains alone check no address");
});

test("delta: adding or narrowing the networks tightens; dropping them or admitting a new network relaxes; domains change nothing", () => {
  const law = (perimeter?: PolicyFileConfig["perimeter"]) => compilePolicy({ specId: "claude-code", document: { models: [corp], ...(perimeter ? { perimeter } : {}) } });
  const d = (a?: PolicyFileConfig["perimeter"], b?: PolicyFileConfig["perimeter"]) => policyDelta(law(a), law(b));
  const add = d(undefined, { networks: ["10.0.0.0/8"] });
  assert.deepEqual([add.relaxations.length, add.tightenings.map((t) => t.facet)], [0, ["perimeter"]]);
  const drop = d({ networks: ["10.0.0.0/8"] }, undefined);
  assert.equal(drop.relaxations.length, 1);
  assert.match(drop.relaxations[0]!.detail, /perimeter\.networks is removed/);
  const widen = d({ networks: ["10.1.0.0/16"] }, { networks: ["10.0.0.0/8"] });
  assert.deepEqual(widen.relaxations.map((r) => r.subject), ["10.0.0.0/8"]);
  const narrow = d({ networks: ["10.0.0.0/8"] }, { networks: ["10.1.0.0/16"] });
  assert.deepEqual([narrow.relaxations.length, narrow.tightenings.map((t) => t.subject)], [0, ["10.0.0.0/8"]]);
  const words = d({ networks: ["10.0.0.0/8"], domains: ["a.example"] }, { networks: ["10.0.0.0/8"], domains: ["b.example"] });
  assert.deepEqual([words.relaxations.length, words.tightenings.length], [0, 0]);
  const still = d({ networks: ["10.0.0.0/8", "fd00::/8"] }, { networks: ["fd00::/8", "10.0.0.0/8"] });
  assert.deepEqual([still.relaxations.length, still.tightenings.length], [0, 0], "the same networks in another order");
});
