/**
 * self-loop.test — unit matrix for isSelfDestination (src/proxy.ts).
 *
 * The self-loop guard refuses a request whose destination is the proxy's OWN
 * listen address (forwarding it recurses into the same listener until ports
 * exhaust — the 35,723-event incident). These cases pin BOTH directions: a true
 * self-target is detected, and — crucially — a DIFFERENT-port loopback service is
 * NOT mistaken for self (no over-block of legitimate local traffic).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { isSelfDestination } from "../../src/proxy.js";

const PORT = 8790;

test("exact self address is a loop", () => {
  assert.equal(isSelfDestination("127.0.0.1:8790", "127.0.0.1", PORT), true);
});

test("loopback aliases of the same port are loops", () => {
  assert.equal(isSelfDestination("localhost:8790", "127.0.0.1", PORT), true);
  assert.equal(isSelfDestination("[::1]:8790", "127.0.0.1", PORT), true);
  assert.equal(isSelfDestination("127.0.0.5:8790", "127.0.0.1", PORT), true, "all of 127/8 is loopback");
});

test("a DIFFERENT port on the same host is NOT a loop (no over-block of local services)", () => {
  assert.equal(isSelfDestination("127.0.0.1:9999", "127.0.0.1", PORT), false);
  assert.equal(isSelfDestination("localhost:3000", "127.0.0.1", PORT), false);
});

test("a different (non-loopback) host on our port is NOT a loop", () => {
  assert.equal(isSelfDestination("example.com:8790", "127.0.0.1", PORT), false);
  assert.equal(isSelfDestination("10.0.0.5:8790", "127.0.0.1", PORT), false);
});

test("a port-less destination defaults to HTTP 80", () => {
  assert.equal(isSelfDestination("127.0.0.1", "127.0.0.1", 80), true);
  assert.equal(isSelfDestination("127.0.0.1", "127.0.0.1", PORT), false, "no port → 80 ≠ 8790");
});

test("binding all interfaces (0.0.0.0) treats loopback targets on our port as self", () => {
  assert.equal(isSelfDestination("127.0.0.1:8790", "0.0.0.0", PORT), true);
  assert.equal(isSelfDestination("localhost:8790", "0.0.0.0", PORT), true);
});

test("an unparseable destination is not classified as self (the normal path handles it)", () => {
  assert.equal(isSelfDestination("", "127.0.0.1", PORT), false);
});
