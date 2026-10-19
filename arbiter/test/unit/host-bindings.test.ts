/**
 * host-bindings.test — the ONE binding rule (policy/host-bindings.ts,
 * confidentiality.md §2.2) that the egress gate, the holder join, the
 * holder-send question, the session sinks and (by its copy) the net-proxy
 * all match by.
 *
 * Pins the table in the module header case by case, then the property the
 * holder join rests on: whenever `bindingCovers(outer, inner)`, every
 * destination `inner` admits, `outer` admits too (a cover never claims more
 * than the matcher grants), over every pair of a binding corpus and a
 * destination corpus.
 *
 * Axes: none (a pure function; no gate runs).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { bindingAdmits, bindingCovers, destinationMatchesBindings } from "../../policy/host-bindings.js";
import { destinationMatchesBindings as gateMatch } from "../../policy/policy-interface.js";
import { bindingCovers as joinCovers, intersectBindings } from "../../policy/flow-taint.js";
import { destinationIsBound } from "../../policy/session-egress.js";
import { hostIsBound } from "../../policy/holder-send-ask.js";
import { hostOfDestination } from "../../ipc/server.js";

const ADMITS: Array<[destination: string, binding: string, admitted: boolean]> = [
  ["example.com", "example.com", true],
  ["api.example.com", "example.com", true],
  ["a.b.example.com", "example.com", true],
  ["evil-example.com", "example.com", false],
  ["example.com.evil.net", "example.com", false],
  ["API.Example.COM", "example.com", true],
  ["example.com.", "example.com", true],
  ["api.example.com", "EXAMPLE.com.", true],
  ["s3.amazonaws.com", "*.amazonaws.com", true],
  ["a.s3.amazonaws.com", "*.amazonaws.com", true],
  ["amazonaws.com", "*.amazonaws.com", false],
  ["evilamazonaws.com", "*.amazonaws.com", false],
  ["db.internal:5432", "db.internal:5432", true],
  ["db.internal:5433", "db.internal:5432", false],
  ["db.internal", "db.internal:5432", true],
  ["db.internal:5432", "db.internal", true],
  ["db.internal:5432", "db.internal:*", true],
  ["x.db.internal:5432", "*.db.internal:5432", true],
  ["x.db.internal:5433", "*.db.internal:5432", false],
  ["https://api.example.com:8443/v1?q=1", "example.com:8443", true],
  ["https://api.example.com:8443/v1", "example.com:443", false],
  ["https://user@api.example.com/v1", "example.com", true],
  ["api.example.com/v1/x", "example.com", true],
  ["10.1.2.3", "10.1.2.3", true],
  ["10.1.2.3:443", "10.1.2.3", true],
  ["10.1.2.4", "10.1.2.3", false],
  ["4.10.1.2.3", "10.1.2.3", false],
  ["10.1.2.3", "10.0.0.0/8", false],
  ["[::1]:443", "[::1]:443", true],
  ["[::1]:80", "[::1]:443", false],
  ["::1", "[::1]", true],
  // IPv6 compared as addresses, in their canonical text (2026-10-17, plan 10
  // §11.13.1); a zone id names an interface, so it matches nothing.
  ["[2001:db8:0::1]:8443", "[2001:DB8::1]:8443", true],
  ["https://[2001:DB8::1]:8443/simple", "[2001:db8::1]", true],
  ["2001:db8::1", "[2001:0db8:0:0:0:0:0:1]", true],
  ["[2001:db8::1]", "[2001:db8::1]:8443", true],
  ["[2001:db8::1]:443", "[2001:db8::1]:8443", false],
  ["[2001:db8::2]", "[2001:db8::1]", false],
  ["[2001:db8::1]", "2001:db8::", false],
  ["[fe80::1%eth0]", "[fe80::1]", false],
  ["[fe80::1]", "[fe80::1%eth0]", false],
  ["[fe80::1%25eth0]", "[fe80::1%25eth0]", false],
  ["fe80::1%eth0", "fe80::1%eth0", false],
  // A stated port (the net-proxy states every destination's, 2026-10-17):
  // a binding with a port admits that port only; one without, every port.
  ["registry.example:443", "registry.example:8443", false],
  ["registry.example:8443", "registry.example:8443", true],
  ["registry.example:443", "registry.example", true],
  ["registry.example:8443", "registry.example", true],
  ["[2001:db8::1]:8443", "[2001:db8::1]:8443", true],
  ["[2001:db8::1]:8443", "[2001:db8::1]", true],
  ["[2001:db8::1]:80", "[2001:db8::1]:8443", false],
  ["example.com", "*", false],
  ["example.com", "unix:/run/example.com", false],
  ["example.com", "mount:nfs4:example.com:/x", false],
  ["example.com", "", false],
  ["example.com", "*.*.com", false],
  ["example.com", "example.com:http", false],
  ["*.example.com", "example.com", false],
  ["", "example.com", false],
];

test("bindingAdmits: the table in the module header, case by case", () => {
  for (const [d, b, want] of ADMITS) {
    assert.equal(bindingAdmits(d, b), want, `${JSON.stringify(b)} admits ${JSON.stringify(d)}: ${want}`);
  }
});

test("every binding check in the arbiter answers by the one rule", () => {
  for (const [d, b, want] of ADMITS) {
    const why = `${JSON.stringify(b)} admits ${JSON.stringify(d)}`;
    assert.equal(destinationMatchesBindings(d, [b]), want, `${why} (host-bindings)`);
    assert.equal(gateMatch(d, [b]), want, `${why} (the egress gate)`);
    assert.equal(hostIsBound(d, [b]), want, `${why} (the holder-send question)`);
    if (d !== "") assert.equal(destinationIsBound(d, [b]), want, `${why} (the session sinks)`);
  }
  assert.equal(joinCovers, bindingCovers, "the holder join covers by the same function");
  assert.equal(destinationMatchesBindings("example.com", []), false);
  assert.equal(destinationMatchesBindings("example.com", null), false);
  assert.equal(destinationMatchesBindings("api.example.com", ["nope.test", "example.com"]), true, "any one binding suffices");
});

const COVERS: Array<[outer: string, inner: string, covers: boolean]> = [
  ["example.com", "api.example.com", true],
  ["example.com", "*.example.com", true],
  ["example.com", "*.api.example.com", true],
  ["*.example.com", "api.example.com", true],
  ["*.example.com", "example.com", false],
  ["*.example.com", "*.api.example.com", true],
  ["*.example.com", "*.example.com", true],
  ["api.example.com", "example.com", false],
  ["api.example.com", "*.example.com", false],
  ["example.com", "evil-example.com", false],
  ["example.com:443", "api.example.com:443", true],
  ["example.com:443", "api.example.com", false],
  ["example.com:443", "api.example.com:80", false],
  ["example.com", "api.example.com:443", true],
  ["10.0.0.0/8", "10.0.0.0/8", true],
  ["10.0.0.0/8", "10.1.2.3", false],
  ["10.1.2.3", "10.1.2.3:443", true],
  ["10.1.2.3:443", "10.1.2.3", false],
  ["example.com", "10.1.2.3", false],
  ["[2001:DB8::1]", "[2001:db8:0::1]:8443", true],
  ["[2001:db8::1]:8443", "[2001:DB8:0::1]", false],
  ["[2001:db8::1]", "[2001:db8::2]", false],
  ["[fe80::1%eth0]", "[fe80::1]", false],
  ["unix:/run/a.sock", "unix:/run/a.sock", true],
  ["unix:/run/a.sock", "unix:/run/A.sock", false],
  ["mount:nfs4:nas:/home", "mount:nfs4:nas:/home", true],
  ["*", "example.com", false],
];

test("bindingCovers: each case", () => {
  for (const [o, i, want] of COVERS) {
    assert.equal(bindingCovers(o, i), want, `${JSON.stringify(o)} covers ${JSON.stringify(i)}: ${want}`);
  }
});

test("a cover never claims more than the matcher grants (the holder join's soundness)", () => {
  const bindings = [...new Set([...ADMITS.map(([, b]) => b), ...COVERS.flatMap(([o, i]) => [o, i]), "example.com:8443", "*.s3.amazonaws.com", "s3.amazonaws.com"])];
  const destinations = [...new Set([...ADMITS.map(([d]) => d), "api.example.com:443", "api.example.com:80", "x.api.example.com", "a.s3.amazonaws.com:443", "10.1.2.3:80"])];
  let pairs = 0;
  for (const outer of bindings) {
    for (const inner of bindings) {
      if (!bindingCovers(outer, inner)) continue;
      pairs++;
      for (const d of destinations) {
        if (bindingAdmits(d, inner)) assert.ok(bindingAdmits(d, outer), `${outer} covers ${inner}, which admits ${d}, so ${outer} must too`);
      }
    }
  }
  assert.ok(pairs > 40, `the corpus exercised the property (${pairs} covering pairs)`);
});

test("the holder join keeps what every file admits, by the same rule", () => {
  // Until 2026-10-11 the join read a bare host as that host only: a holder of
  // a file bound to example.com and one bound to api.example.com could send
  // nowhere, though the gate released each at api.example.com.
  assert.deepEqual(intersectBindings([["example.com"], ["api.example.com"]]), ["api.example.com"]);
  assert.deepEqual(intersectBindings([["*.example.com"], ["example.com"]]), ["*.example.com"]);
  assert.deepEqual(intersectBindings([["*.example.com"], ["api.example.com"]]), ["api.example.com"]);
  assert.deepEqual(intersectBindings([["example.com:443"], ["api.example.com"]]), [], "a port the other file does not pin is not assumed");
  assert.deepEqual(intersectBindings([["example.com"], ["other.test"]]), []);
});

test("hostOfDestination (the user rules' host): a port and brackets are dropped, an IPv6 literal is its address (2026-10-17)", () => {
  assert.equal(hostOfDestination("registry.example:443"), "registry.example");
  assert.equal(hostOfDestination("https://API.Example.com:8443/v1"), "api.example.com");
  assert.equal(hostOfDestination("[2001:db8::1]:443"), "2001:db8::1", "it read `2001` before");
  assert.equal(hostOfDestination("https://u@[::1]:8080/x"), "::1");
  assert.equal(hostOfDestination("10.1.2.3:80"), "10.1.2.3");
});
