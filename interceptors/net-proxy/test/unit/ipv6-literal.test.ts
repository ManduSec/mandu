/**
 * ipv6-literal — the net-proxy's handling of an IPv6-literal destination
 * (plan 10 §11.13.1, 2026-10-17: a pip index on `https://[2001:db8::1]:8443`):
 *
 *   - a CONNECT target comes back bracketed in its canonical text, so the
 *     gate, the leaf certificate and the dial all see one form; one with a
 *     zone id stays as written (no binding admits it);
 *   - the dial takes the address bare (Node looks a bracketed one up as a
 *     name, which fails), and the always-denied check still reads it;
 *   - the inspecting leaf for an address carries an IP entry, not a DNS name
 *     (pip, like every TLS client, checks the address against it);
 *   - mock-site routes match an address in any of its spellings.
 *
 * Pure (the leaf test needs openssl and self-SKIPs without it). No arbiter
 * is built, so no axes are stated.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { X509Certificate } from "node:crypto";

import { parseConnectTarget } from "../../src/proxy.js";
import { connectAuthority } from "../../src/mitm.js";
import { blockedHostReason, dialHostOf } from "../../src/blocked-destinations.js";
import { normalizeHost } from "../../src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";

test("parseConnectTarget: an IPv6 literal comes back bracketed and canonical; a zone id or a name as before", () => {
  assert.deepEqual(parseConnectTarget("[2001:DB8:0::1]:8443"), { host: "[2001:db8::1]", port: 8443 });
  assert.deepEqual(parseConnectTarget("[2001:db8:0:0:0:0:0:1]"), { host: "[2001:db8::1]", port: 443 });
  assert.deepEqual(parseConnectTarget("[::1]:443"), { host: "[::1]", port: 443 });
  assert.deepEqual(parseConnectTarget("[fe80::1%25eth0]:443"), { host: "[fe80::1%25eth0]", port: 443 }, "a zone id: as written, which no binding admits");
  assert.deepEqual(parseConnectTarget("pypi.corp.example:8443"), { host: "pypi.corp.example", port: 8443 });
  assert.deepEqual(parseConnectTarget("pypi.corp.example"), { host: "pypi.corp.example", port: 443 });
});

test("dialHostOf: an IPv6 literal dials bare; the always-denied check reads either form", () => {
  assert.equal(dialHostOf("[2001:db8::1]"), "2001:db8::1");
  assert.equal(dialHostOf("2001:db8::1"), "2001:db8::1");
  assert.equal(dialHostOf("pypi.corp.example"), "pypi.corp.example");
  assert.equal(dialHostOf("127.0.0.1"), "127.0.0.1");
  assert.ok(blockedHostReason("[fe80::1]", 443), "link-local, bracketed");
  assert.ok(blockedHostReason(dialHostOf("[fe80::1]"), 443), "link-local, bare");
  assert.equal(connectAuthority("[2001:db8::1]", 8443), "[2001:db8::1]:8443", "the re-originated Host header");
  assert.equal(connectAuthority("[2001:db8::1]", 443), "[2001:db8::1]");
});

test("normalizeHost: an IPv6 address in any spelling is one route", () => {
  assert.equal(normalizeHost("[2001:DB8:0::1]:8443"), "2001:db8::1");
  assert.equal(normalizeHost("2001:0db8::0001"), "2001:db8::1");
  assert.equal(normalizeHost("[::1]:443"), "::1");
  assert.equal(normalizeHost("Pypi.Corp.Example:8443"), "pypi.corp.example");
});

test("leafForHost: an IPv6 CONNECT target gets an IP entry for the bare address", { skip: !opensslAvailable() && "openssl unavailable" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-np-v6leaf-"));
  try {
    const ca = ensureCa(join(dir, "ca"));
    const v6 = new X509Certificate(leafForHost(ca, "[2001:db8::1]").certPem);
    assert.ok(v6.checkIP("2001:db8::1"), `the leaf names the address: ${v6.subjectAltName}`);
    assert.equal(v6.checkIP("2001:db8::2"), undefined, "and no other");
    const name = new X509Certificate(leafForHost(ca, "pypi.corp.example").certPem);
    assert.equal(name.checkHost("pypi.corp.example"), "pypi.corp.example");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
