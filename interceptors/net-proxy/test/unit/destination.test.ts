/**
 * destination — what the egress proxy states as the destination of every
 * release and binding decision (plan 10 §11.13.1, 2026-10-17): the host and
 * its port, always, so a binding or wire grant with a port is held to it.
 *
 *   - the TLS-inspected leg and the blind tunnel: the CONNECT target's port;
 *   - the plain-HTTP leg: the URL's port, or the scheme's default;
 *   - an IPv6 address bracketed.
 *
 * And by the one binding rule (the proxy's copy): the stated `host:443` is
 * not admitted by a `host:8443` binding (the host alone was, before), and a
 * portless binding still admits every port.
 *
 * Pure. No arbiter is built, so no axes are stated.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { forwardDestination, statedDestination } from "../../src/destination.js";
import { bindingAdmits } from "../../src/host-bindings.js";
import { hostIsBound } from "../../src/egress.js";

test("statedDestination: host:port, an IPv6 address bracketed once", () => {
  assert.equal(statedDestination("registry.example", 443), "registry.example:443");
  assert.equal(statedDestination("registry.example", 8443), "registry.example:8443");
  assert.equal(statedDestination("[2001:db8::1]", 8443), "[2001:db8::1]:8443");
  assert.equal(statedDestination("2001:db8::1", 443), "[2001:db8::1]:443");
  assert.equal(statedDestination("10.1.2.3", 80), "10.1.2.3:80");
});

test("forwardDestination: the URL's port, else its scheme's default; the host as written when it does not parse", () => {
  assert.equal(forwardDestination({ host: "a.example", absoluteUrl: "http://a.example/x" }), "a.example:80");
  assert.equal(forwardDestination({ host: "a.example:8080", absoluteUrl: "http://a.example:8080/x" }), "a.example:8080");
  assert.equal(forwardDestination({ host: "a.example", absoluteUrl: "https://a.example/x" }), "a.example:443");
  assert.equal(forwardDestination({ host: "[::1]:8080", absoluteUrl: "http://[::1]:8080/simple" }), "[::1]:8080");
  assert.equal(forwardDestination({ host: "[2001:db8::1]", absoluteUrl: "http://[2001:DB8:0::1]/" }), "[2001:db8::1]:80");
  assert.equal(forwardDestination({ host: "odd host", absoluteUrl: "http://odd host/" }), "odd host");
});

test("by the binding rule, the stated destination holds a ported binding to its port; a portless binding admits every port", () => {
  for (const [host, port, binding, want] of [
    ["registry.example", 8443, "registry.example:8443", true],
    ["registry.example", 443, "registry.example:8443", false],
    ["registry.example", 443, "registry.example", true],
    ["registry.example", 8443, "registry.example", true],
    ["[2001:db8::1]", 8443, "[2001:db8::1]:8443", true],
    ["[2001:db8::1]", 443, "[2001:db8::1]:8443", false],
    ["[2001:db8::1]", 443, "[2001:db8::1]", true],
  ] as const) {
    const d = statedDestination(host, port);
    assert.equal(bindingAdmits(d, binding), want, `${binding} admits ${d}`);
    assert.equal(hostIsBound(d, [binding]), want, `the holder check: ${binding} admits ${d}`);
  }
  // What the inspected leg stated before: the host alone, which a ported binding admitted at any port.
  assert.equal(bindingAdmits("registry.example", "registry.example:8443"), true, "the hole the stated port closes");
});
