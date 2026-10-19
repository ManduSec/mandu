/**
 * read-gate.test — which dashboard reads may carry a real value, and the
 * Host check (src/server/read-gate.ts; dashboard.md §6 "Reads and the admin
 * session"). Mandu-new.
 *
 * Pure, no socket (value-gate.test.ts in test/component runs the same table
 * over a real server):
 *   - the ROUTE REGISTRY: every `/api/` path server.ts and its route modules
 *     match is named by READ_ROUTES (or is a write-only path listed below),
 *     so a new GET cannot slip in unclassified; a path no entry names is
 *     `admin` (fail closed) — so is every route of an extension that brings
 *     no row (the developer view's rows are its own, dashboard.md §4.25ac);
 *   - the value-bearing routes are never `open`;
 *   - sameOriginRead: the CSRF header or the browser's own Sec-Fetch-Site;
 *   - parseHostHeader / hostAllowed: loopback at the bound port, configured
 *     names, everything else (a rebinding page's name, a missing Host) refused.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  READ_ROUTES, readAccessOf, readRouteOf, sameOriginRead, parseHostHeader, hostAllowed, isLoopbackName,
} from "../../../src/server/read-gate.js";


const SRC = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "..", "src");

/** Paths server.ts answers only to a write (POST/DELETE): no GET to gate. */
const WRITE_ONLY = new Set([
  "/api/session", "/api/control/dashboard/restart", "/api/control/start-all", "/api/control/stop-all",
  "/api/control/restart-all", "/api/run/x/cancel", "/api/test/cancel", "/api/drills/cancel",
  "/api/prompt-filters/reveal", "/api/prompt-filters/bench", "/api/prompt-filters/change",
  "/api/prompt-filters/pack-edit", "/api/prompt-filters/holds/answer", "/api/prompt-filters/let-through",
  "/api/secrets/label", "/api/secrets/derived", "/api/files/impact", "/api/files/move-page-rules",
  "/api/files/labels", "/api/suggestions/scan", "/api/suggestions/apply", "/api/suggestions/dismiss",
  "/api/suggestions/model/preview", "/api/suggestions/model/send", "/api/policy/rules",
  "/api/policy/rules/change", "/api/policy/models/change", "/api/policy/prompt-filters/change",
  "/api/policy/sensitivity-labels/change", "/api/policy/models/test", "/api/policy/export-labels",
  "/api/policy/proposals/x", "/api/policy/changes/x/undo", "/api/policy/assistant",
  "/api/policy/assistant/try", "/api/policy/assistant/apply", "/api/policy/test-flow",
  "/api/policy/posture", "/api/egress/approvals/x/approve", "/api/egress/approvals/x/forget",
  "/api/egress/approvals/x/approve-once", "/api/egress/approvals/x/deny", "/api/egress/approvals/x/always-source",
  "/api/egress/approvals/x/send-without",
  "/api/control/x/start", "/api/control/x/stop", "/api/control/x/restart", "/api/control/x/replace",
  "/api/home/reveal",
]);

/** Concrete paths for a route regex's source: `[^/]+` and `.+` as `x`, and
 *  one path per alternative of each group. */
function samplesOf(re: string): string[] {
  const base = re
    .replace(/^\^/, "").replace(/\$$/, "")
    .replace(/\(\[\^\/\]\+\)|\[\^\/\]\+|\(\.\+\)|\.\+/g, "x")
    .replace(/\\\//g, "/");
  const expand = (s: string): string[] => {
    const m = /\((?:\?:)?([^()]*)\)/.exec(s);
    if (!m) return [s];
    return m[1]!.split("|").flatMap((alt) => expand(s.slice(0, m.index) + alt + s.slice(m.index + m[0].length)));
  };
  return expand(base);
}

const tsIn = (dir: string): string[] => readdirSync(join(SRC, dir)).filter((f) => f.endsWith(".ts")).map((f) => join(SRC, dir, f));

/** Every `/api/` path a dispatch names: string comparisons and route
 *  regexes. Default: the product's server (server.ts and src/server/*.ts);
 *  `tsIn("inspector")`: the inspector's extension. */
function dispatchedPaths(files = [join(SRC, "server.ts"), ...tsIn("server")]): string[] {
  const out = new Set<string>();
  for (const f of files) {
    if (f.endsWith("read-gate.ts")) continue;
    const text = readFileSync(f, "utf8");
    for (const m of text.matchAll(/(?:urlPath|drillsPath)\s*===\s*"(\/api\/[^"]+)"/g)) out.add(m[1]!);
    for (const m of text.matchAll(/(?:urlPath|drillsPath)\.match\(\s*\/(\^\\\/api\\\/[^\n]*?)\/\s*,?\s*\)/g)) for (const p of samplesOf(m[1]!)) out.add(p);
    for (const m of text.matchAll(/\/(\^\\\/api\\\/[^\n]*?\$)\/\.exec\(urlPath\)/g)) for (const p of samplesOf(m[1]!)) out.add(p);
  }
  return [...out].sort();
}

test("registry: every /api/ path the product's server dispatches is named by READ_ROUTES or is write-only", () => {
  const paths = dispatchedPaths();
  assert.ok(paths.length > 30, `the scan found the routes (${paths.length})`);
  const unnamed = paths.filter((p) => !WRITE_ONLY.has(p) && readRouteOf(p) === null);
  assert.deepEqual(unnamed, [], "a GET route with no READ_ROUTES entry: classify it in src/server/read-gate.ts");
  // The scan reaches the routes it must: the value-bearing ones among them.
  for (const p of ["/api/events", "/api/stream", "/api/home/agent"]) {
    assert.ok(paths.includes(p), `the scan found ${p}`);
  }
});



test("a path no entry names is admin (fail closed)", () => {
  assert.equal(readRouteOf("/api/brand-new-route"), null);
  assert.equal(readAccessOf("/api/brand-new-route"), "admin");
});

test("the value-bearing routes are never open", () => {
  const expected: Array<[string, string]> = [
    ["/api/events", "projection"], ["/api/stream", "projection"], ["/api/home/agent", "projection"],
    ["/api/prompt-filters/holds", "admin"], ["/api/policy/prompt-filters", "admin"], ["/api/files/list", "admin"],
    ["/api/suggestions", "admin"], ["/api/policy/sensitivity-labels", "admin"],
    // an extension's route is admin unless it brings its row
    ["/api/fs", "admin"], ["/api/control/arbiter/logs", "admin"], ["/api/policy/document", "admin"],
  ];
  for (const [path, access] of expected) assert.equal(readAccessOf(path), access, path);
  // and their open neighbours stay open
  for (const path of ["/api/sessions", "/api/home", "/api/policy/panel", "/api/control/summary"]) {
    assert.equal(readAccessOf(path), "open", path);
  }
  for (const r of READ_ROUTES) assert.ok(r.why.length > 8, `every entry says why: ${String(r.path)}`);
});

test("Answered earlier past its newest 20 is read as /api/home is: open, with its query, and nothing past it (dashboard.md §4.25 *Past the newest 20*)", () => {
  assert.equal(readAccessOf("/api/home/answered"), "open");
  assert.equal(readAccessOf("/api/home/answered"), readAccessOf("/api/home"), "the same access as the newest 20");
  assert.equal(readRouteOf("/api/home/answered")?.path, "/api/home/answered", "its own entry, not a neighbour's");
  // A path under it is no route: unlisted, so admin (fail closed).
  assert.equal(readAccessOf("/api/home/answered/x"), "admin");
});

test("sameOriginRead: the CSRF header, or the browser's same-origin / typed navigation", () => {
  assert.equal(sameOriginRead({ "x-mandu-control": "1" }), true);
  assert.equal(sameOriginRead({ "sec-fetch-site": "same-origin" }), true);
  assert.equal(sameOriginRead({ "sec-fetch-site": "none" }), true);
  assert.equal(sameOriginRead({ "sec-fetch-site": "cross-site" }), false);
  assert.equal(sameOriginRead({ "sec-fetch-site": "same-site" }), false);
  assert.equal(sameOriginRead({}), false, "no header: the cookie alone does not show values");
});

test("parseHostHeader: names, ports, IPv6 brackets; malformed is null", () => {
  assert.deepEqual(parseHostHeader("127.0.0.1:4500"), { name: "127.0.0.1", port: 4500 });
  assert.deepEqual(parseHostHeader("LocalHost:4500"), { name: "localhost", port: 4500 });
  assert.deepEqual(parseHostHeader("[::1]:4500"), { name: "::1", port: 4500 });
  assert.deepEqual(parseHostHeader("dash.example.org"), { name: "dash.example.org", port: null });
  for (const bad of [undefined, "", "::1", "a b", "host:99999", "host:x", "[::1", "evil/x:1"]) {
    assert.equal(parseHostHeader(bad), null, String(bad));
  }
});

test("hostAllowed: loopback at the bound port; configured names; a rebinding page's name refused", () => {
  assert.equal(isLoopbackName("127.3.4.5"), true);
  assert.equal(isLoopbackName("localhost.evil.example"), false);
  const ok = (h: string | undefined, names: string[] = [], addr = "127.0.0.1") => hostAllowed(h, 4500, addr, names);
  assert.equal(ok("127.0.0.1:4500"), true);
  assert.equal(ok("localhost:4500"), true);
  assert.equal(ok("[::1]:4500"), true);
  assert.equal(ok("127.0.0.1:4501"), false, "another port is another origin");
  assert.equal(ok("localhost"), false, "no port means 80");
  assert.equal(ok("attacker.example:4500"), false, "DNS rebinding: the page's own name");
  assert.equal(ok(undefined), false, "no Host at all");
  assert.equal(ok("dash.example.org", ["dash.example.org"]), true, "a configured name, any port");
  assert.equal(ok("dash.example.org:8443", ["dash.example.org:443"]), false, "a configured name:port, that port only");
  assert.equal(ok("10.0.0.5:4500", [], "10.0.0.5"), true, "the bound address itself");
  assert.equal(ok("0.0.0.0:4500", [], "0.0.0.0"), false, "a wildcard bind is no name");
  const own = new Set(["192.0.2.10"]);
  assert.equal(hostAllowed("192.0.2.10:4500", 4500, "0.0.0.0", [], own), true, "one of this host's own addresses, at the port");
  assert.equal(hostAllowed("192.0.2.10:4501", 4500, "0.0.0.0", [], own), false);
  assert.equal(hostAllowed("192.0.2.11:4500", 4500, "0.0.0.0", [], own), false, "another host's address");
  assert.equal(hostAllowed("127.0.0.1:4500", null, null, []), false, "not listening yet");
  assert.equal(hostAllowed("localhost", 80, "127.0.0.1", []), true, "bound to 80, no port is 80");
});
