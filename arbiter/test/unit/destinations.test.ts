/**
 * destinations.test — policy.yaml `destinations:` (policy-surface.md
 * §2.3, stage 4b): the validator (allow-only, port/proto/host shapes), the
 * compile (lists expanded, defaults applied), the connect-guard spec export
 * (`connectAllowSpecs`, what the launcher appends WITHOUT narrowing), and
 * the relaxation each allowance is.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { compilePolicy, connectAllowSpecs, relaxationsOf } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";

test("validator: a well-formed destinations list passes; every malformed field is named", () => {
  assert.deepEqual(validatePolicyDocument({
    version: 1,
    lists: { registries: ["registry.npmjs.org", "pypi.org"] },
    destinations: [
      { host: "@registries", connect: "allow" },
      { host: "10.0.0.0/8", port: "*", proto: "udp", connect: "allow", reason: "lab" },
      { host: "*.internal.example", port: 8443, connect: "allow" },
    ],
  }), []);
  const problems = validatePolicyDocument({
    version: 1,
    destinations: [
      { host: "a.example", port: 0, connect: "allow" },
      { host: "b.example", port: 70000, proto: "sctp", connect: "allow" },
      { host: "c.example", connect: "deny" },
      { host: "d.example", connect: "maybe", extra: 1 },
      "not a mapping",
    ],
  });
  assert.ok(problems.some((p) => /destinations\[0\]\.port: must be an integer 1–65535 or "\*"/.test(p)));
  assert.ok(problems.some((p) => /destinations\[1\]\.port/.test(p)) && problems.some((p) => /destinations\[1\]\.proto: must be tcp \| udp/.test(p)));
  assert.ok(problems.some((p) => /destinations\[2\]\.connect: "deny" is not enforceable yet/.test(p) && /user_rules \(kind: release, mode: block\)/.test(p)), "deny is refused WITH the alternative");
  assert.ok(problems.some((p) => /destinations\[3\]\.connect: must be "allow"/.test(p)) && problems.some((p) => /destinations\[3\]: unknown key 'extra'/.test(p)));
  assert.ok(problems.some((p) => /destinations\[4\]: must be a mapping/.test(p)));
  assert.ok(validatePolicyDocument({ version: 1, destinations: "x" }).some((p) => /destinations: must be a list/.test(p)));
});

test("compile: lists expand to one rule per host; port 443 / tcp are the defaults; specs dedupe; only allow exports", () => {
  const document: PolicyFileConfig = {
    version: 1,
    lists: { registries: ["registry.npmjs.org", "PyPI.org"] },
    destinations: [
      { host: "@registries", connect: "allow", reason: "installs" },
      { host: "10.0.0.0/8", port: "*", proto: "udp", connect: "allow" },
      { host: "registry.npmjs.org", connect: "allow" }, // duplicate spec → once
    ],
  } as PolicyFileConfig;
  const c = compilePolicy({ specId: "claude-code", document });
  assert.deepEqual(c.destinations.map((d) => [d.host, d.port, d.proto, d.connect]), [
    ["registry.npmjs.org", 443, "tcp", "allow"],
    ["pypi.org", 443, "tcp", "allow"],
    ["10.0.0.0/8", "*", "udp", "allow"],
    ["registry.npmjs.org", 443, "tcp", "allow"],
  ]);
  assert.equal(c.destinations[0]!.reason, "installs");
  assert.deepEqual(connectAllowSpecs(c), ["tcp:registry.npmjs.org:443", "tcp:pypi.org:443", "udp:10.0.0.0/8:*"]);
  // Every allowance is a relaxation (it widens strict/curated launches).
  const relax = relaxationsOf(c).filter((r) => r.kind === "connect-allow");
  assert.deepEqual(relax.map((r) => r.subject), ["tcp:registry.npmjs.org:443", "tcp:pypi.org:443", "udp:10.0.0.0/8:*"]);
  assert.match(relax[0]!.detail, /every launch posture .*applies at the next launch/);
  // The built-ins alone export nothing and relax nothing.
  const builtin = compilePolicy({ specId: "claude-code", document: null });
  assert.deepEqual(builtin.destinations, []);
  assert.deepEqual(connectAllowSpecs(builtin), []);
});
