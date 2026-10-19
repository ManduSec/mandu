/**
 * blocked-destinations.test — the always-denied egress set (cloud metadata,
 * link-local) and the resolve-then-check lookup. A twin of the connect guard's
 * `guard.rs::blocked_destination` tests; the two lists must agree.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  blockedAddressReason,
  blockedHostReason,
  guardedLookup,
  isBlockedDestinationError,
  type DialPolicy,
} from "../../src/blocked-destinations.js";

test("metadata and credential endpoints are denied on every port", () => {
  for (const ip of [
    "169.254.169.254",
    "169.254.170.2",
    "169.254.170.23",
    "100.100.100.200",
    "fd00:ec2::254",
    "fd00:ec2:0:0:0:0:0:254",
    "fd00:ec2::23",
    "[fd00:ec2::254]",
    // The same endpoint in v4-mapped and NAT64 dress.
    "::ffff:169.254.169.254",
    "::ffff:a9fe:a9fe",
    "64:ff9b::169.254.169.254",
    "64:ff9b::a9fe:a9fe",
  ]) {
    for (const port of [53, 80, 443]) {
      assert.ok(blockedAddressReason(ip, port), `${ip}:${port}`);
    }
  }
});

test("the rest of link-local is denied off DNS, and DNS survives", () => {
  assert.equal(blockedAddressReason("169.254.1.1", 8080), "link-local address");
  assert.equal(blockedAddressReason("fe80::1", 443), "link-local address");
  assert.equal(blockedAddressReason("fe80::1%eth0", 443), "link-local address");
  assert.equal(blockedAddressReason("febf::1", 80), "link-local address");
  // A VPC resolver on link-local keeps answering.
  assert.equal(blockedAddressReason("169.254.169.253", 53), null);
  assert.equal(blockedAddressReason("fe80::53", 53), null);
});

test("ordinary addresses and names are not refused", () => {
  for (const ip of ["1.2.3.4", "127.0.0.1", "10.0.0.1", "100.100.100.201", "::1", "2001:db8::1", "fec0::1", "fd00:ec2::255"]) {
    assert.equal(blockedAddressReason(ip, 80), null, ip);
  }
  assert.equal(blockedAddressReason("example.com", 80), null, "a name is not an address");
  assert.equal(blockedHostReason("example.com", 443), null);
});

test("metadata names are refused by name, case and trailing dot ignored", () => {
  for (const h of ["metadata.google.internal", "METADATA.google.internal.", "metadata.goog", "metadata.azure.internal", "instance-data"]) {
    assert.ok(blockedHostReason(h, 80), h);
  }
  assert.ok(blockedHostReason("169.254.169.254", 80));
  assert.ok(blockedHostReason("[fd00:ec2::254]", 80));
});

function lookupOnce(host: string, all: boolean, policy: DialPolicy = {}): Promise<{ err: NodeJS.ErrnoException | null; address: unknown }> {
  return new Promise((resolve) => {
    guardedLookup(80, policy)(host, all ? { all: true } : {}, (err, address) => resolve({ err, address }));
  });
}

test("guardedLookup refuses a numeric name that resolves to the metadata endpoint", async () => {
  // getaddrinfo reads 2852039166 as 169.254.169.254 (inet_aton forms): the
  // check runs on what the name resolved to, not on how it was spelled.
  const r = await lookupOnce("2852039166", false);
  assert.ok(isBlockedDestinationError(r.err), String(r.err));
  assert.match(r.err!.message, /cloud metadata endpoint/);
  const named = await lookupOnce("metadata.google.internal", true);
  assert.ok(isBlockedDestinationError(named.err), "refused by name without asking DNS");
});

test("guardedLookup hands back exactly what it checked, in both callback shapes", async () => {
  // A numeric name resolves with no network (getaddrinfo reads it as is).
  const one = await lookupOnce("192.0.2.7", false);
  assert.equal(one.err, null);
  assert.equal(one.address, "192.0.2.7");
  const all = await lookupOnce("192.0.2.7", true);
  assert.equal(all.err, null);
  assert.deepEqual(all.address, [{ address: "192.0.2.7", family: 4 }]);
  // Loopback passes only when this machine is allowed (a route's own dial).
  const local = await lookupOnce("127.0.0.1", true, { allowThisMachine: true });
  assert.equal(local.err, null);
  assert.deepEqual(local.address, [{ address: "127.0.0.1", family: 4 }]);
});
