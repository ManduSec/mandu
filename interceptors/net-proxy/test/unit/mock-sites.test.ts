/**
 * mock-sites.test — unit matrix for MockSites (src/mock-sites.ts).
 *
 * The egress proxy can serve canned web responses for configured URLs instead of
 * forwarding (an OFFLINE mock web server, Mandu-style url→fixture). This lets a
 * REAL Claude Code agent run a deterministic fetch→write→read loop without hitting
 * the internet, while the response still flows through the proxy's ingress
 * symbolization. These cases pin the YAML shape, matching, and body sources.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { MockSites, normalizeHost, parseLoopbackDial } from "../../src/mock-sites.js";

test("an inline body is served for an exact-URL match; an unknown URL → null", () => {
  const m = MockSites.fromYaml(`
sites:
  - url: "http://example.com/setup-guide"
    body: "<h1>setup</h1>"
`);
  const hit = m.match("http://example.com/setup-guide");
  assert.ok(hit, "the configured URL matches");
  assert.equal(hit!.body.toString("utf8"), "<h1>setup</h1>");
  assert.equal(hit!.status, 200, "default status is 200");
  assert.match(String(hit!.headers["content-type"]), /text\/html/, "default content-type is text/html");
  assert.equal(m.match("http://example.com/other"), null, "an unconfigured URL is not mocked");
});

test("status + content_type overrides are honored", () => {
  const m = MockSites.fromYaml(`
sites:
  - url: "http://api.test/data.json"
    status: 201
    content_type: "application/json"
    body: '{"ok":true}'
`);
  const hit = m.match("http://api.test/data.json");
  assert.equal(hit!.status, 201);
  assert.match(String(hit!.headers["content-type"]), /application\/json/);
});

test("body_file is read relative to the YAML's directory", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-mock-"));
  try {
    writeFileSync(join(dir, "guide.html"), "FILE BODY");
    const m = MockSites.fromYaml(
      `
sites:
  - url: "http://example.com/g"
    body_file: "guide.html"
`,
      dir,
    );
    assert.equal(m.match("http://example.com/g")!.body.toString("utf8"), "FILE BODY");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("matching is robust to a trailing slash and host case", () => {
  const m = MockSites.fromYaml(`
sites:
  - url: "http://Example.com/setup-guide/"
    body: "x"
`);
  assert.ok(m.match("http://example.com/setup-guide"), "trailing slash + host case normalize");
  assert.ok(m.match("http://EXAMPLE.com/setup-guide/"), "exact-ish variants still match");
});

test("an empty / siteless config yields a no-op mock (matches nothing)", () => {
  assert.equal(MockSites.fromYaml("sites: []").size, 0);
  assert.equal(MockSites.fromYaml("sites: []").match("http://x/"), null);
});

test("a site missing both body and body_file is rejected (fail loud at load)", () => {
  assert.throws(() => MockSites.fromYaml(`sites:\n  - url: "http://x/"`), /body/i);
});

test("then_body: the first match serves body, every later match serves then_body", () => {
  const m = MockSites.fromYaml(`
sites:
  - url: "http://example.test/flaky"
    status: 503
    body: "maintenance notice"
    then_body: "the real page"
    then_status: 200
`);
  const first = m.match("http://example.test/flaky")!;
  assert.equal(first.body.toString("utf8"), "maintenance notice");
  assert.equal(first.status, 503);
  const second = m.match("http://example.test/flaky")!;
  assert.equal(second.body.toString("utf8"), "the real page");
  assert.equal(second.status, 200);
  const third = m.match("http://example.test/flaky")!;
  assert.equal(third.body.toString("utf8"), "the real page", "then_body persists from the second match on");
});

test("then_body: a site WITHOUT it keeps serving the same body forever (no behavior change)", () => {
  const m = MockSites.fromYaml(`
sites:
  - url: "http://example.test/stable"
    body: "same"
`);
  assert.equal(m.match("http://example.test/stable")!.body.toString("utf8"), "same");
  assert.equal(m.match("http://example.test/stable")!.body.toString("utf8"), "same");
});

test("then_body: state is per-instance — a fresh MockSites starts at body again", () => {
  const yamlText = `
sites:
  - url: "http://example.test/flaky"
    body: "first"
    then_body: "rest"
`;
  const a = MockSites.fromYaml(yamlText);
  assert.equal(a.match("http://example.test/flaky")!.body.toString("utf8"), "first");
  assert.equal(a.match("http://example.test/flaky")!.body.toString("utf8"), "rest");
  const b = MockSites.fromYaml(yamlText);
  assert.equal(b.match("http://example.test/flaky")!.body.toString("utf8"), "first", "a new instance is unserved");
});

// ── host routes (the replay runner's per-host catch-all, 2026-10-01) ──────────

test("a host route parses: `to` and `tls_to` are loopback dials; host matching ignores case, port and a trailing dot", () => {
  const m = MockSites.fromYaml(`
sites:
  - url: "http://httpbin.org/exact"
    body: "exact"
hosts:
  - host: "HTTPBin.org"
    to: "127.0.0.1:41234"
    tls_to: "127.0.0.1:41235"
  - host: "example.com"
    tls_to: "[::1]:443"
  - host: "notes-sink.test"
    to: "localhost:8080"
`);
  assert.equal(m.size, 1);
  assert.equal(m.routeCount, 3);
  assert.deepEqual(m.route("httpbin.org"), { http: { host: "127.0.0.1", port: 41234 }, tls: { host: "127.0.0.1", port: 41235 } });
  assert.deepEqual(m.route("HTTPBIN.ORG:80"), m.route("httpbin.org."), "case, a port and a trailing dot do not matter");
  assert.deepEqual(m.route("example.com"), { tls: { host: "::1", port: 443 } }, "a route may name only one of the two");
  assert.deepEqual(m.route("notes-sink.test"), { http: { host: "localhost", port: 8080 } });
  assert.equal(m.route("other.test"), null, "an unrouted host has no route");
  assert.equal(m.route("sub.httpbin.org"), null, "a route is per host, never per suffix");
  assert.equal(m.match("http://httpbin.org/exact")!.body.toString("utf8"), "exact", "an exact site still matches beside a route");
});

test("a host route never points off the machine: a non-loopback, portless or malformed target throws", () => {
  for (const to of ["10.0.0.1:80", "example.com:80", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:70000", "127.300.0.1:80", "[::2]:80", "0.0.0.0:80", 42]) {
    assert.throws(() => MockSites.fromYaml(`hosts:\n  - host: "a.test"\n    to: ${JSON.stringify(to)}\n`), /mock-sites: host route 'a\.test' to/, `to: ${String(to)}`);
  }
  assert.throws(() => MockSites.fromYaml(`hosts:\n  - host: "a.test"\n`), /needs 'to' or 'tls_to'/);
  assert.throws(() => MockSites.fromYaml(`hosts:\n  - to: "127.0.0.1:1"\n`), /non-empty 'host'/);
  assert.throws(() => MockSites.fromYaml(`hosts:\n  - host: "a.test"\n    to: "127.0.0.1:1"\n  - host: "A.test"\n    to: "127.0.0.1:2"\n`), /listed twice/);
  assert.throws(() => MockSites.fromYaml(`hosts: "a.test"\n`), /'hosts' must be a list/);
});

test("parseLoopbackDial and normalizeHost", () => {
  assert.deepEqual(parseLoopbackDial("127.0.0.2:9", "x"), { host: "127.0.0.2", port: 9 });
  assert.deepEqual(parseLoopbackDial(" [::1]:65535 ", "x"), { host: "::1", port: 65535 });
  assert.equal(normalizeHost("[::1]:443"), "::1");
  assert.equal(normalizeHost("::1"), "::1");
  assert.equal(normalizeHost("Example.COM.:8443"), "example.com");
});

test("the `*` host route takes every host without its own route; tls_ca is read relative to the YAML and needs a tls_to", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-mock-"));
  try {
    writeFileSync(join(dir, "ca.pem"), "PEM BYTES");
    const m = MockSites.fromYaml(`hosts:\n  - host: "a.test"\n    to: "127.0.0.1:1"\n  - host: "*"\n    to: "127.0.0.1:2"\n    tls_to: "127.0.0.1:3"\n    tls_ca: "ca.pem"\n`, dir);
    assert.deepEqual(m.route("a.test"), { http: { host: "127.0.0.1", port: 1 } }, "a host's own route wins");
    assert.deepEqual(m.route("github.com"), { http: { host: "127.0.0.1", port: 2 }, tls: { host: "127.0.0.1", port: 3, ca: "PEM BYTES" } });
    assert.throws(() => MockSites.fromYaml(`hosts:\n  - host: "a.test"\n    to: "127.0.0.1:1"\n    tls_ca: "ca.pem"\n`, dir), /tls_ca must be a file path, beside a tls_to/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
