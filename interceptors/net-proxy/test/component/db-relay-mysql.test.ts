/**
 * db-relay-mysql — the database login release for MySQL
 * (db-login-release.md §8): a client logs in through the relay with the
 * placeholder its `~/.my.cnf` or `MYSQL_PWD` holds; the relay gets it by
 * `caching_sha2_password`'s full path (cleartext inside the client's TLS,
 * or under the relay's RSA key), and answers the server's
 * `mysql_native_password` or `caching_sha2_password` with the value the
 * egress gate put back.
 *
 * A real NetProxy with one relay, a mock arbiter, a fake MySQL server
 * (test/fake-mysql.ts) that records every byte it receives, and a client
 * that logs in as `mysql` does.
 *
 * Mandu-new (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { NetProxy, type NetProxyOptions } from "../../src/proxy.js";
import { MockArbiter, type MockArbiterOptions, type DesymbolizationRequest } from "../../src/arbiter-client.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";
import { mysqlLogin, startFakeMysql, type FakeMysqlOptions } from "../fake-mysql.js";

const SYM = "$MDU:nomodel_Read[c1d2].client.password";
const REAL = "myRealPW_DBRELAY_8m";
const DB = "mysql.internal:3306";
const OPENSSL = opensslAvailable();

const allowAtDb = (req: DesymbolizationRequest) =>
  req.destination === DB && JSON.stringify(req.positions) === JSON.stringify(["authorization"])
    ? { allow: true, requiresApproval: false, reason: "bound" }
    : { allow: false, requiresApproval: true, reason: `not bound at ${req.destination}` };

async function rig(server: FakeMysqlOptions, arb: MockArbiterOptions = {}, extra: Partial<NetProxyOptions> = {}) {
  const db = await startFakeMysql(server);
  const arbiter = new MockArbiter({ decisionFn: allowAtDb, values: { [SYM]: REAL }, ...arb });
  const proxy = new NetProxy({
    arbiter, log: (m) => process.env["DBG"] && console.error(m), sessionId: "sess-my",
    attributeHolders: () => [{ procKey: "4200-1", ancestors: [] }],
    dbRelays: [{ protocol: "mysql", host: "mysql.internal", port: 3306 }],
    dbRoutes: new Map([[DB, { host: "127.0.0.1", port: db.port }]]),
    // The fake server is this test's own process: told apart from the
    // session's by default (the check's own case is below).
    dbLocalServer: () => "other",
    ...extra,
  });
  await proxy.listen(0);
  const [bound] = await proxy.listenDbRelays();
  return {
    port: bound!.listen, arbiter, db,
    events: () => arbiter.emittedEvents as Array<Record<string, unknown>>,
    close: async () => { await proxy.close(); await db.close(); },
  };
}

const noReal = (b: Buffer, what: string): void => assert.ok(!b.toString("latin1").includes(REAL), `${what}: the real password`);

/** A session CA dir and a server certificate for mysql.internal from a CA of its own. */
function certs(dir: string) {
  const serverCa = ensureCa(join(dir, "server-ca"));
  const leaf = leafForHost(serverCa, "mysql.internal");
  return { serverCa: readFileSync(serverCa.certPath, "utf8"), tls: { key: leaf.keyPem, cert: leaf.certPem }, sessionDir: join(dir, "session-ca") };
}

test("native server, client by RSA (no TLS): the placeholder logs in, nothing on any wire carries the password", async () => {
  const r = await rig({ plugin: "native", user: "alice", password: REAL });
  try {
    const res = await mysqlLogin(r.port, { user: "alice", password: SYM, publicKey: true });
    assert.equal(res.ok, true, res.error);
    assert.equal(res.info, "ECHO SELECT 1");
    assert.deepEqual(r.db.logins, [{ user: "alice", ok: true, tls: false, path: "native" }]);
    noReal(r.db.received(), "the server");
    noReal(res.received, "the client");
    assert.ok(!r.db.received().toString("latin1").includes("$MDU:"), "no placeholder at the server");
    assert.deepEqual(r.arbiter.decisionCalls.map((d) => [d.symbol, d.destination, d.positions, d.scheme]), [[SYM, DB, ["authorization"], "mysql"]], "the relay states its scheme: a ~/.my.cnf grant is put back only there");
    assert.ok(r.events().some((e) => e["action"] === "forwarded" && e["scheme"] === "mysql"));
  } finally { await r.close(); }
});

test("caching_sha2 server on its fast path; a client that starts with mysql_native_password is switched", async () => {
  const r = await rig({ plugin: "caching_sha2", user: "alice", password: REAL, cached: true });
  try {
    const res = await mysqlLogin(r.port, { user: "alice", password: SYM, publicKey: true, clientPlugin: "native" });
    assert.equal(res.ok, true, res.error);
    assert.deepEqual(r.db.logins.map((l) => l.path), ["fast"]);
    noReal(r.db.received(), "the server");
  } finally { await r.close(); }
});

test("a server auth switch to mysql_native_password is followed", async () => {
  const r = await rig({ plugin: "caching_sha2", user: "alice", password: REAL, cached: true, switchToNative: true });
  try {
    const res = await mysqlLogin(r.port, { user: "alice", password: SYM, publicKey: true });
    assert.equal(res.ok, true, res.error);
    assert.deepEqual(r.db.logins.map((l) => l.path), ["native"]);
  } finally { await r.close(); }
});

test("caching_sha2's full path needs the password itself: refused without TLS Mandu verified, sent over it", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  const unverified = await rig({ plugin: "caching_sha2", user: "alice", password: REAL, cached: false });
  try {
    const res = await mysqlLogin(unverified.port, { user: "alice", password: SYM, publicKey: true });
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /full authentication.*verified/);
    noReal(unverified.db.received(), "the server");
  } finally { await unverified.close(); }
  const dir = mkdtempSync(join(tmpdir(), "mdu-my-tls-"));
  try {
    const c = certs(dir);
    const r = await rig({ plugin: "caching_sha2", user: "alice", password: REAL, cached: false, tls: c.tls }, {}, { mitm: { caDir: c.sessionDir }, dbMysqlUpstreamCa: c.serverCa });
    try {
      const sessionCa = readFileSync(join(c.sessionDir, "mandu-egress-ca.pem"), "utf8");
      const res = await mysqlLogin(r.port, { user: "alice", password: SYM, tls: { ca: sessionCa, servername: "mysql.internal" } });
      assert.equal(res.ok, true, res.error);
      assert.deepEqual(r.db.logins, [{ user: "alice", ok: true, tls: true, path: "full" }]);
      noReal(res.received, "the client");
    } finally { await r.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("an unbound database, the arbiter gone, a tainted holder: refused; the server's method gets nothing", async () => {
  const cases: Array<[string, MockArbiterOptions, RegExp]> = [
    ["unbound", { decisionFn: () => ({ allow: false, requiresApproval: true, reason: "secret not bound" }) }, /was not put back/],
    ["arbiter gone", { failDecision: true }, /arbiter unreachable/],
    ["tainted holder", { secretTaint: { "4200-1": { tainted: true, level: "no-model", files: ["/h/.aws/credentials"], bindings: ["*.amazonaws.com"] } } }, /was refused/],
  ];
  for (const [name, arb, why] of cases) {
    const r = await rig({ plugin: "native", user: "alice", password: REAL }, arb);
    try {
      const res = await mysqlLogin(r.port, { user: "alice", password: SYM, publicKey: true });
      assert.equal(res.ok, false, name);
      assert.match(res.error ?? "", why, name);
      assert.deepEqual(r.db.logins, [], `${name}: no login at the server`);
      noReal(r.db.received(), name);
      if (name === "tainted holder") assert.equal(r.db.connections(), 0, "the server is never dialed");
    } finally { await r.close(); }
  }
});

test("a client with neither TLS nor a public-key request cannot log in (as against a real server); the server's own refusal is passed on", async () => {
  const r = await rig({ plugin: "native", user: "alice", password: REAL });
  try {
    const res = await mysqlLogin(r.port, { user: "alice", password: SYM });
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /Authentication requires secure connection/, "the client's own refusal, as mysql's");
    assert.deepEqual(r.db.logins, [], "nothing reached the server's method");
    const wrong = await mysqlLogin(r.port, { user: "bob", password: SYM, publicKey: true });
    assert.equal(wrong.ok, false);
    assert.match(wrong.error ?? "", /Access denied for user 'bob'/);
  } finally { await r.close(); }
});

test("security review 2026-10-24: a session-owned local listener, a server without TLS when ~/.my.cnf names an ssl-ca, and a registered value in a connect attribute: refused before the password goes", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  const session = await rig({ plugin: "native", user: "alice", password: REAL }, {}, { dbLocalServer: () => "session" });
  try {
    const res = await mysqlLogin(session.port, { user: "alice", password: SYM, publicKey: true });
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /a program of this session/);
    assert.equal(session.db.received().length, 0, "the server got no byte");
  } finally { await session.close(); }

  const dir = mkdtempSync(join(tmpdir(), "mdu-my-strip-"));
  try {
    const c = certs(dir);
    // The server offers no TLS (its flag stripped in the path); the user's ssl-ca says it must.
    const stripped = await rig({ plugin: "native", user: "alice", password: REAL }, {}, { dbMysqlUpstreamCa: c.serverCa });
    try {
      const res = await mysqlLogin(stripped.port, { user: "alice", password: SYM, publicKey: true });
      assert.equal(res.ok, false);
      assert.match(res.error ?? "", /does not offer TLS, and your ~\/\.my\.cnf names an ssl-ca/);
      assert.deepEqual(stripped.db.logins, []);
      noReal(stripped.db.received(), "the stripped server");
    } finally { await stripped.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }

  const attr = await rig({ plugin: "native", user: "alice", password: REAL }, {
    fingerprintSecrets: [{ symbol: SYM, value: REAL, level: "no-model", bindings: ["other.db:3306"] }],
  });
  try {
    const res = await mysqlLogin(attr.port, { user: "alice", password: SYM, publicKey: true, attr: `x-${REAL}` });
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /fingerprint tripwire/);
    assert.deepEqual(attr.db.logins, []);
  } finally { await attr.close(); }
});
