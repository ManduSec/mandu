/**
 * dashboard-auth.test.ts — the live suites' dashboard credentials
 * (lib/dashboard-auth.ts): env-var first, the systemd env file second, a
 * silent no-header fallback, and the 401 hint that never echoes a secret.
 *
 * Run: npm test
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";

import {
  DASHBOARD_ENV_FILE,
  dashboardAuthHeaders,
  parseEnvFile,
  resolveDashboardBasicAuth,
  unauthorizedHint,
} from "../lib/dashboard-auth.js";

test("the env file is the path table's dashboard-env under HOME (on-disk-layout.md §5)", () => {
  assert.equal(DASHBOARD_ENV_FILE, join(".mandu", "dashboard.env"));
});

test("parseEnvFile: KEY=VALUE, comments, blanks, export prefix, quotes, first-= split", () => {
  const parsed = parseEnvFile([
    "# Mandu dashboard: HTTP Basic auth",
    "",
    "DASHBOARD_BASIC_AUTH=alice:p=ss:w0rd",
    'export OTHER="quoted value"',
    "SINGLE='x'",
    "  SPACED = has spaces ",
    "=novalue",
    "bad key=1",
    "NOEQ",
  ].join("\n"));
  assert.deepEqual(parsed, {
    DASHBOARD_BASIC_AUTH: "alice:p=ss:w0rd",
    OTHER: "quoted value",
    SINGLE: "x",
    SPACED: "has spaces",
  });
});

test("resolveDashboardBasicAuth: env wins, then the env file, else undefined; malformed pairs are ignored", () => {
  const home = "/home/x";
  const file = join(home, DASHBOARD_ENV_FILE);
  const readFile = (p: string) => {
    assert.equal(p, file);
    return "DASHBOARD_BASIC_AUTH=filer:secret\n";
  };
  assert.equal(resolveDashboardBasicAuth({ DASHBOARD_BASIC_AUTH: "envr:pw" }, home, readFile), "envr:pw");
  assert.equal(resolveDashboardBasicAuth({}, home, readFile), "filer:secret");
  assert.equal(resolveDashboardBasicAuth({ DASHBOARD_BASIC_AUTH: "nocolon" }, home, readFile), "filer:secret", "a malformed env value falls through");
  assert.equal(resolveDashboardBasicAuth({ DASHBOARD_BASIC_AUTH: ":nouser" }, home, readFile), "filer:secret");
  assert.equal(resolveDashboardBasicAuth({}, home, () => { throw new Error("ENOENT"); }), undefined);
  assert.equal(resolveDashboardBasicAuth({}, home, () => "# empty\n"), undefined);
});

test("dashboardAuthHeaders: RFC 7617 Basic header, or no header at all", () => {
  assert.deepEqual(dashboardAuthHeaders({ DASHBOARD_BASIC_AUTH: "alice:pw" }, "/nohome", () => { throw new Error("ENOENT"); }), {
    Authorization: `Basic ${Buffer.from("alice:pw").toString("base64")}`,
  });
  assert.deepEqual(dashboardAuthHeaders({}, "/nohome", () => { throw new Error("ENOENT"); }), {});
});

test("unauthorizedHint names the fix without echoing a value", () => {
  assert.match(unauthorizedHint(false), /DASHBOARD_BASIC_AUTH=user:password/);
  assert.match(unauthorizedHint(false), /dashboard\.env/);
  assert.match(unauthorizedHint(true), /does not match/);
  assert.ok(!unauthorizedHint(true).includes("secret"));
});
