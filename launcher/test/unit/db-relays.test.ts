/**
 * db-relays — which databases a launch opens a login relay for, how the
 * egress proxy is told and its relays' ports read back, and how the connect
 * guard is pointed at them (db-login-release.md).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  MAX_DB_RELAYS, dbGuardRedirects, dbRelayPorts, dbRelayTargets, mycnfTargets, mysqlEnvTargets, parseDbRelayPorts, pgEnvTargets, pgpassTargets, writeDbRootCert,
  type DbRelayBound,
} from "../../src/db-relays.js";
import { computeNetGuardSpecs, planNetGuard, sessionProxyPorts } from "../../src/net-guard.js";
import { startNetProxy } from "../../src/services/net-proxy.js";
import { Layout } from "../../src/services/layout.js";
import type { ServiceDeps } from "../../src/services/primitives.js";
import type { LaunchPlan } from "../../src/types.js";
import { sessionLogins } from "../../src/agent-login.js";
import { netProxyDenyHosts } from "../../src/upload-deny.js";
import { modelHostDenyFor } from "../../src/model-host-deny.js";

test("pgpass: each line's host and port; a * port is 5432; a * host, a socket directory and junk name none", () => {
  const text = [
    "# a comment",
    "db.internal:5432:app:alice:s3cret",
    "Analytics.Corp:*:*:bob:pw",
    "*:5432:*:carol:pw",
    "/var/run/postgresql:5432:*:dave:pw",
    "2001\\:db8\\:\\:7:6432:*:erin:pw\\:with\\:colons",
    "bad host:5432:a:b:c",
    "db.internal:99999:a:b:c",
    "too:few:fields",
    "",
  ].join("\n");
  assert.deepEqual(pgpassTargets(text), [
    { protocol: "postgres", host: "db.internal", port: 5432 },
    { protocol: "postgres", host: "analytics.corp", port: 5432 },
    { protocol: "postgres", host: "2001:db8::7", port: 6432 },
  ]);
});

test("PGHOST / PGPORT name databases only when PGPASSWORD is set; a socket directory names none", () => {
  assert.deepEqual(pgEnvTargets({ PGHOST: "db.internal" }), [], "no password variable");
  assert.deepEqual(pgEnvTargets({ PGPASSWORD: "x", PGHOST: "db.internal" }), [{ protocol: "postgres", host: "db.internal", port: 5432 }]);
  assert.deepEqual(pgEnvTargets({ PGPASSWORD: "x", PGHOST: "a.corp,b.corp", PGPORT: "5432,6543" }), [
    { protocol: "postgres", host: "a.corp", port: 5432 },
    { protocol: "postgres", host: "b.corp", port: 6543 },
  ]);
  assert.deepEqual(pgEnvTargets({ PGPASSWORD: "x", PGHOST: "a.corp,b.corp", PGPORT: "6000" }).map((t) => t.port), [6000, 6000], "one port for every host");
  assert.deepEqual(pgEnvTargets({ PGPASSWORD: "x", PGHOST: "/tmp" }), []);
  assert.deepEqual(pgEnvTargets({ PGPASSWORD: "x" }), [], "no host: libpq's socket");
});

test("dbRelayTargets: PGPASSFILE wins over ~/.pgpass, the two sources are merged without duplicates, the list is capped", () => {
  const files: Record<string, string> = {
    "/h/.pgpass": "db.internal:5432:*:alice:pw\n",
    "/elsewhere/pgpass": "other.db:5432:*:alice:pw\n",
  };
  const read = (p: string): string => { if (p in files) return files[p]!; throw new Error("ENOENT"); };
  assert.deepEqual(dbRelayTargets({ PGPASSWORD: "x", PGHOST: "db.internal" }, "/h", read).targets, [{ protocol: "postgres", host: "db.internal", port: 5432 }]);
  assert.deepEqual(dbRelayTargets({ PGPASSFILE: "/elsewhere/pgpass" }, "/h", read).targets.map((t) => t.host), ["other.db"]);
  assert.deepEqual(dbRelayTargets({}, "/nohome", read), { targets: [], cut: 0 }, "no file: none");
  const many = Array.from({ length: MAX_DB_RELAYS + 3 }, (_, i) => `db${i}.corp:5432:*:u:p`).join("\n");
  const capped = dbRelayTargets({}, "/h", () => many);
  assert.equal(capped.targets.length, MAX_DB_RELAYS);
  assert.equal(capped.cut, 3);
});

test("MySQL: each ~/.my.cnf section with a password at the host and port it or [client] names; MYSQL_HOST with MYSQL_PWD; localhost is the socket", () => {
  const text = "[client]\nhost=mysql.internal\npassword=pw\n\n[mysqldump]\nport=3307\npassword=pw2\n\n[mysql_local]\nhost=localhost\npassword=pw3\n\n[mysql_nopw]\nhost=other.db\n";
  assert.deepEqual(mycnfTargets(text), [
    { protocol: "mysql", host: "mysql.internal", port: 3306 },
    { protocol: "mysql", host: "mysql.internal", port: 3307 },
  ]);
  assert.deepEqual(mysqlEnvTargets({ MYSQL_HOST: "m.corp" }), [], "no password variable");
  assert.deepEqual(mysqlEnvTargets({ MYSQL_PWD: "x", MYSQL_HOST: "m.corp", MYSQL_TCP_PORT: "3310" }), [{ protocol: "mysql", host: "m.corp", port: 3310 }]);
  assert.deepEqual(mysqlEnvTargets({ MYSQL_PWD: "x", MYSQL_HOST: "localhost" }), []);
  const read = (p: string): string => { if (p === "/h/.my.cnf") return text; throw new Error("ENOENT"); };
  assert.deepEqual(dbRelayTargets({}, "/h", read).targets.map((t) => `${t.protocol}:${t.host}:${t.port}`), ["mysql:mysql.internal:3306", "mysql:mysql.internal:3307"]);
});

test("the relay port file: only targets the launch asked for, on a real port", () => {
  const asked = [{ protocol: "postgres" as const, host: "db.internal", port: 5432 }];
  const text = JSON.stringify([
    { protocol: "postgres", host: "db.internal", port: 5432, listen: 41000 },
    { protocol: "postgres", host: "evil.example", port: 5432, listen: 41001 },
    { protocol: "postgres", host: "db.internal", port: 5432, listen: 0 },
  ]);
  assert.deepEqual(parseDbRelayPorts(text, asked), [{ protocol: "postgres", host: "db.internal", port: 5432, listen: 41000 }]);
  assert.deepEqual(parseDbRelayPorts("garbage", asked), []);
});

test("the guard: a redirect per relay (an IPv6 database bracketed), the relay ports allowed on loopback and excepted for holders", () => {
  const relays: DbRelayBound[] = [
    { protocol: "postgres", host: "db.internal", port: 5432, listen: 41000 },
    { protocol: "postgres", host: "2001:db8::7", port: 6432, listen: 41001 },
  ];
  assert.deepEqual(dbGuardRedirects(relays), ["tcp:db.internal:5432=127.0.0.1:41000", "tcp:[2001:db8::7]:6432=127.0.0.1:41001"]);
  assert.deepEqual(dbRelayPorts(relays), [41000, 41001]);
  const specs = computeNetGuardSpecs({ targetProxyPort: 8788, netProxyPort: 8790, ullmForwarderPort: null, apiHost: null, strict: true, dbRelayPorts: [41000] });
  assert.ok(specs.includes("tcp:127.0.0.0/8:41000") && specs.includes("tcp:[::1]:41000"), specs.join(" "));
  assert.ok(!specs.some((s) => s.includes(":5432")), "the database itself is never allowed");
  assert.deepEqual(sessionProxyPorts({ netProxyPort: 8790, dbRelayPorts: [41000, 41001] }), [8790, 41000, 41001]);
  const { wrapArgv } = planNetGuard({ binPath: "/bin/guard", specs: ["tcp:127.0.0.1:8788"], redirects: dbGuardRedirects(relays) });
  assert.deepEqual(wrapArgv, ["/bin/guard", "--allow", "tcp:127.0.0.1:8788", "--redirect", "tcp:db.internal:5432=127.0.0.1:41000", "--redirect", "tcp:[2001:db8::7]:6432=127.0.0.1:41001", "--skip-unsupported", "--"]);
});

test("PGSSLROOTCERT for the agent: the user's own root certificate, then the session CA", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-dbroot-"));
  try {
    const ca = join(dir, "session.pem");
    writeFileSync(ca, "-----BEGIN CERTIFICATE-----\nSESSION\n-----END CERTIFICATE-----\n");
    mkdirSync(join(dir, "home", ".postgresql"), { recursive: true });
    writeFileSync(join(dir, "home", ".postgresql", "root.crt"), "-----BEGIN CERTIFICATE-----\nUSER\n-----END CERTIFICATE-----\n");
    const out = writeDbRootCert(dir, ca, {}, join(dir, "home"))!;
    const pem = readFileSync(out, "utf8");
    assert.ok(pem.indexOf("USER") >= 0 && pem.indexOf("USER") < pem.indexOf("SESSION"), pem);
    const named = join(dir, "named.pem");
    writeFileSync(named, "-----BEGIN CERTIFICATE-----\nNAMED\n-----END CERTIFICATE-----\n");
    assert.match(readFileSync(writeDbRootCert(dir, ca, { PGSSLROOTCERT: named }, join(dir, "home"))!, "utf8"), /NAMED[\s\S]*SESSION/);
    assert.doesNotMatch(readFileSync(writeDbRootCert(dir, ca, {}, join(dir, "none"))!, "utf8"), /USER/, "no root: the session CA alone");
    assert.equal(writeDbRootCert(dir, join(dir, "missing.pem"), {}, dir), undefined);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid-db", tenant: "live", arbiterSock: "/run/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu",
    eventDir: "/run/sid/events", cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: true, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true,
    effectiveAxes: { integrity: false, confidentiality: true }, ...over,
  };
}

test("startNetProxy: the launch's databases go to the proxy, and the relays it opened come back for the guard", async () => {
  const saved = process.env["MANDU_NET_PROXY_PORT"];
  process.env["MANDU_NET_PROXY_PORT"] = "0";
  const dir = mkdtempSync(join(tmpdir(), "mdu-dbrelay-svc-"));
  try {
    const home = join(dir, "home");
    mkdirSync(home);
    writeFileSync(join(home, ".pgpass"), "db.internal:5432:app:alice:s3cret\n");
    let env: Record<string, string | undefined> = {};
    // What this launch's own proxy publishes (the identity check after the start).
    const ident = (p: LaunchPlan, dbRelays?: unknown) => ({
      mandu: true, service: "net-proxy", arbiterSock: "/run/b.sock", sessionLogins: sessionLogins(p, process.env, home),
      denyHosts: netProxyDenyHosts(p),
      ...(modelHostDenyFor(p.effectiveAxes?.confidentiality === true) ? { modelHostDeny: ["api.anthropic.com"] } : {}),
      ...(dbRelays !== undefined ? { dbRelays } : {}),
    });
    const deps = (relayAnswer: (asked: string) => string | null): ServiceDeps => ({
      home,
      probePort: async () => true,
      probeIdentity: async () => ident(plan(), JSON.parse(relayAnswer(env["MANDU_NET_PROXY_DB_RELAYS"]!) ?? "[]")),
      waitFor: async (check) => Boolean(await check()),
      waitForFile: async (p) => existsSync(p),
      startDetachedCmd: (_c, _a, o) => {
        env = o.env;
        writeFileSync(env["MANDU_PORT_FILE"]!, "45001");
        const answer = relayAnswer(env["MANDU_NET_PROXY_DB_RELAYS"]!);
        if (answer !== null && env["MANDU_DB_RELAY_PORT_FILE"]) writeFileSync(env["MANDU_DB_RELAY_PORT_FILE"], answer);
        return { pid: 1, stop: () => {} };
      },
      runOnce: () => ({ status: 0, stdout: "", stderr: "" }),
    });
    const open = (asked: string) => JSON.stringify((JSON.parse(asked) as object[]).map((t, i) => ({ ...t, listen: 42000 + i })));
    const r = await startNetProxy(plan(), Layout.dev("/repo"), dir, deps(open));
    assert.deepEqual(JSON.parse(env["MANDU_NET_PROXY_DB_RELAYS"]!), [{ protocol: "postgres", host: "db.internal", port: 5432 }]);
    assert.equal(env["MANDU_DB_RELAY_PORT_FILE"], join(dir, "net-proxy-db-relays.json"));
    assert.deepEqual(r.dbRelays, [{ protocol: "postgres", host: "db.internal", port: 5432, listen: 42000 }]);
    assert.equal(r.dbNote, undefined);

    // The relays never published: the launch goes on without them, and says so.
    const none = await startNetProxy(plan(), Layout.dev("/repo"), dir, deps(() => null));
    assert.equal(none.dbRelays, undefined);
    assert.match(none.dbNote ?? "", /1 database login relay\(s\) did not open/);

    // The confidentiality axis off: no relay is asked for.
    const off = plan({ effectiveAxes: { integrity: true, confidentiality: false } });
    await startNetProxy(off, Layout.dev("/repo"), dir, { ...deps(open), probeIdentity: async () => ident(off) });
    assert.equal(env["MANDU_NET_PROXY_DB_RELAYS"], "[]");
    assert.equal(env["MANDU_DB_RELAY_PORT_FILE"], undefined);
  } finally {
    if (saved === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = saved;
    rmSync(dir, { recursive: true, force: true });
  }
});
