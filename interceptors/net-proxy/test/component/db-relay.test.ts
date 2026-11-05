/**
 * db-relay — the database login release at the network exit
 * (db-login-release.md): a client logs in through the relay with the
 * placeholder its password file or variable holds, and the relay answers the
 * server's own method (SCRAM-SHA-256, md5) with the value the egress gate put
 * back, only at the database the relay serves and only when the gate allows.
 *
 * A real NetProxy with one relay, a mock arbiter, a fake Postgres server
 * (test/fake-postgres.ts) that records every byte it receives, and a client
 * that answers a cleartext request as psql does. The oracle: the real
 * password never reaches the client, a refused login gets nothing from the
 * server's method, and SCRAM's and md5's exchanges never carry the password
 * itself.
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
import { parseDbRelays } from "../../src/db-relay.js";
import { pgLogin, startFakePostgres, type FakePostgresOptions } from "../fake-postgres.js";

const SYM = "$MDU:nomodel_Read[a1b2].alice.password";
const REAL = "pgRealPW_DBRELAY_7q2";
const DB = "db.internal:5432";

const allowAtDb = (req: DesymbolizationRequest) =>
  req.destination === DB && JSON.stringify(req.positions) === JSON.stringify(["authorization"])
    ? { allow: true, requiresApproval: false, reason: "bound" }
    : { allow: false, requiresApproval: true, reason: `not bound at ${req.destination} (${JSON.stringify(req.positions)})` };

interface Rig {
  port: number;
  arbiter: MockArbiter;
  db: Awaited<ReturnType<typeof startFakePostgres>>;
  events: () => Array<Record<string, unknown>>;
  close: () => Promise<void>;
}

async function rig(server: FakePostgresOptions, arb: MockArbiterOptions = {}, extra: Partial<NetProxyOptions> = {}): Promise<Rig> {
  const db = await startFakePostgres(server);
  const arbiter = new MockArbiter({ decisionFn: allowAtDb, values: { [SYM]: REAL }, ...arb });
  const proxy = new NetProxy({
    arbiter, log: () => {}, sessionId: "sess-db",
    attributeHolders: () => [{ procKey: "4100-1", ancestors: [] }],
    dbRelays: [{ protocol: "postgres", host: "db.internal", port: 5432 }],
    dbRoutes: new Map([[DB, { host: "127.0.0.1", port: db.port }]]),
    // The fake server is this test's own process: told apart from the
    // session's by default (the check's own cases are below).
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

function noPassword(buf: Buffer, what: string): void {
  const s = buf.toString("latin1");
  assert.ok(!s.includes(REAL), `${what}: the real password`);
}

test("parseDbRelays: postgres and mysql host:port entries kept, anything else dropped", () => {
  const r = parseDbRelays(JSON.stringify([
    { protocol: "postgres", host: "db.internal", port: 5432 },
    { protocol: "postgres", host: "db.internal", port: 5432 },
    { protocol: "mysql", host: "m", port: 3306 },
    { protocol: "postgres", host: "bad host", port: 5432 },
    { protocol: "postgres", host: "h", port: 0 },
  ]));
  assert.deepEqual(r.targets, [{ protocol: "postgres", host: "db.internal", port: 5432 }, { protocol: "mysql", host: "m", port: 3306 }]);
  assert.equal(r.dropped.length, 2);
  assert.equal(parseDbRelays(JSON.stringify([{ protocol: "oracle", host: "o", port: 1521 }])).dropped.length, 1);
  assert.deepEqual(parseDbRelays("not json"), { targets: [], dropped: ["not json"] });
  assert.deepEqual(parseDbRelays(undefined), { targets: [], dropped: [] });
});

for (const method of ["scram", "md5"] as const) {
  test(`${method}: the placeholder logs in at the bound database; neither the client nor the wire ever carries the password`, async () => {
    const r = await rig({ method, user: "alice", password: REAL });
    try {
      const res = await pgLogin(r.port, { user: "alice", password: SYM, database: "app" });
      assert.equal(res.ok, true, res.error);
      assert.equal(res.tag, "ECHO SELECT 1", "the session works after the login");
      assert.deepEqual(r.db.logins, [{ user: "alice", ok: true, tls: false }]);
      noPassword(res.received, "what the client received");
      noPassword(r.db.received(), `what the server received (${method} never sends the password)`);
      assert.ok(!r.db.received().toString("latin1").includes("$MDU:"), "the server never sees the placeholder");
      const d = r.arbiter.decisionCalls;
      assert.equal(d.length, 1);
      assert.deepEqual([d[0]!.symbol, d[0]!.destination, d[0]!.positions, d[0]!.scheme], [SYM, DB, ["authorization"], "postgres"], "the relay states its scheme: the arbiter puts a .pgpass grant back only there");
      const fwd = r.events().find((e) => e["action"] === "forwarded");
      assert.ok(fwd && fwd["scheme"] === "postgres" && JSON.stringify(fwd["resolved"]) === JSON.stringify([SYM]), JSON.stringify(r.events()));
    } finally { await r.close(); }
  });
}

test("md5 is answered as the user's own psql would: plain md5 to a local listener outside the session goes; PGREQUIREAUTH=scram-sha-256 refuses it before the password is asked for", async () => {
  const plain = await rig({ method: "md5", user: "alice", password: REAL });
  try {
    const res = await pgLogin(plain.port, { user: "alice", password: SYM });
    assert.equal(res.ok, true, res.error);
  } finally { await plain.close(); }
  const strict = await rig({ method: "md5", user: "alice", password: REAL }, {}, { dbPgSettings: { requireAuth: "scram-sha-256" } });
  try {
    const res = await pgLogin(strict.port, { user: "alice", password: SYM });
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /asks for md5, which your PGREQUIREAUTH=scram-sha-256 rules out/);
    assert.equal(strict.arbiter.decisionCalls.length, 0, "the password is never asked for");
    assert.ok(!strict.db.received().toString("latin1").includes("md5"), "no md5 answer was sent");
  } finally { await strict.close(); }
  // A session-owned listener: refused before any byte, md5 included.
  const session = await rig({ method: "md5", user: "alice", password: REAL }, {}, { dbLocalServer: () => "session" });
  try {
    const res = await pgLogin(session.port, { user: "alice", password: SYM });
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /a program of this session/);
    assert.equal(session.db.received().length, 0);
  } finally { await session.close(); }
});

test("SCRAM with fewer than 4096 iterations: refused before the proof is sent", async () => {
  const r = await rig({ method: "scram", user: "alice", password: REAL, iterations: 1 });
  try {
    const res = await pgLogin(r.port, { user: "alice", password: SYM });
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /iteration count of 1/);
    assert.deepEqual(r.db.logins, []);
  } finally { await r.close(); }
});

test("a database on this machine whose listening end is a program of the session, or one Mandu cannot read: refused before anything is sent", async () => {
  for (const [who, why] of [["session", /a program of this session/], ["unknown", /could not tell who listens/]] as const) {
    const r = await rig({ method: "scram", user: "alice", password: REAL }, {}, { dbLocalServer: () => who });
    try {
      const res = await pgLogin(r.port, { user: "alice", password: SYM });
      assert.equal(res.ok, false, who);
      assert.match(res.error ?? "", why);
      assert.equal(r.arbiter.decisionCalls.length, 0, `${who}: nothing asked`);
      assert.equal(r.db.received().length, 0, `${who}: the server got no byte`);
    } finally { await r.close(); }
  }
});

test("the user's own libpq settings: PGSSLMODE=verify-full with no root certificate, PGREQUIREAUTH and PGCHANNELBINDING=require are held to", async () => {
  const cases: Array<[NetProxyOptions["dbPgSettings"], FakePostgresOptions["method"], RegExp]> = [
    [{ sslmode: "verify-full" }, "scram", /PGSSLMODE=verify-full asks for a verified server|does not offer TLS/],
    [{ requireAuth: "scram-sha-256" }, "trust", /asks for none, which your PGREQUIREAUTH=scram-sha-256 rules out/],
    [{ requireAuth: "!password" }, "password", /asks for password, which your PGREQUIREAUTH=!password rules out/],
    [{ channelBinding: "require" }, "scram", /PGCHANNELBINDING=require cannot be met/],
  ];
  for (const [settings, method, why] of cases) {
    const r = await rig({ method, user: "alice", password: REAL }, {}, { dbPgSettings: settings });
    try {
      const res = await pgLogin(r.port, { user: "alice", password: SYM });
      assert.equal(res.ok, false, JSON.stringify(settings));
      assert.match(res.error ?? "", why, JSON.stringify(settings));
      // (A trust server counts its own login done before it says so; the
      // client is refused all the same, with nothing of the password sent.)
      if (method !== "trust") assert.deepEqual(r.db.logins.filter((l) => l.ok), [], JSON.stringify(settings));
      noPassword(r.db.received(), JSON.stringify(settings));
    } finally { await r.close(); }
  }
});

test("an unbound database: the gate refuses, the client gets the reason, the server's method gets nothing", async () => {
  const r = await rig({ method: "scram", user: "alice", password: REAL }, { decisionFn: () => ({ allow: false, requiresApproval: true, reason: "secret not bound to db.internal:5432 → approval required" }) });
  try {
    const res = await pgLogin(r.port, { user: "alice", password: SYM });
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /mandu: the password for db\.internal:5432 was not put back: .*not bound/);
    assert.deepEqual(r.db.logins, [], "no login reached the server");
    assert.ok(!r.db.received().includes(Buffer.from("SCRAM-SHA-256")), "no SCRAM exchange was started");
    noPassword(r.db.received(), "the server");
    noPassword(res.received, "the client");
    assert.ok(r.events().some((e) => e["action"] === "blocked" && e["scheme"] === "postgres"));
  } finally { await r.close(); }
});

test("the arbiter unreachable: refused (fail-closed), nothing sent", async () => {
  const r = await rig({ method: "scram", user: "alice", password: REAL }, { failDecision: true });
  try {
    const res = await pgLogin(r.port, { user: "alice", password: SYM });
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /arbiter unreachable/);
    assert.deepEqual(r.db.logins, []);
  } finally { await r.close(); }
});

test("a process holding a secret bound elsewhere: refused before its startup reaches the server, trust login or not", async () => {
  for (const method of ["scram", "trust"] as const) {
    const r = await rig({ method, user: "alice", password: REAL }, {
      secretTaint: { "4100-1": { tainted: true, level: "no-model", files: ["/h/.aws/credentials"], bindings: ["*.amazonaws.com"] } },
    });
    try {
      const res = await pgLogin(r.port, { user: "alice", password: SYM });
      assert.equal(res.ok, false, method);
      assert.match(res.error ?? "", /the connection to db\.internal:5432 was refused/);
      assert.equal(r.arbiter.decisionCalls.length, 0, "the per-symbol gate is never reached");
      assert.equal(r.db.connections(), 0, `${method}: the server is never dialed (a startup's parameters could carry the secret)`);
    } finally { await r.close(); }
  }
});

test("the tripwire over the startup: a registered value in a parameter is refused before the server is dialed", async () => {
  const r = await rig({ method: "trust", user: REAL, password: "" }, {
    fingerprintSecrets: [{ symbol: SYM, value: REAL, level: "no-model", bindings: ["other.db:5432"] }],
  });
  try {
    const res = await pgLogin(r.port, { user: REAL, password: "" });
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /fingerprint tripwire/);
    assert.equal(r.db.connections(), 0);
  } finally { await r.close(); }
});

test("SCRAM: a server that cannot prove it knows the password is cut off", async () => {
  const r = await rig({ method: "scram", user: "alice", password: REAL, badSignature: true });
  try {
    const res = await pgLogin(r.port, { user: "alice", password: SYM });
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /did not prove it knows the password/);
    noPassword(res.received, "the client");
  } finally { await r.close(); }
});

test("a trust login: no password is asked for, nothing is resolved", async () => {
  const r = await rig({ method: "trust", user: "alice", password: "" });
  try {
    const res = await pgLogin(r.port, { user: "alice", password: SYM });
    assert.equal(res.ok, true, res.error);
    assert.equal(r.arbiter.decisionCalls.length, 0);
  } finally { await r.close(); }
});

test("a cleartext request with no verified TLS, and a method Mandu does not answer: refused, the password never sent", async () => {
  for (const method of ["password", "gss"] as const) {
    const r = await rig({ method, user: "alice", password: REAL });
    try {
      const res = await pgLogin(r.port, { user: "alice", password: SYM });
      assert.equal(res.ok, false, method);
      assert.match(res.error ?? "", method === "password" ? /only over TLS to a server whose certificate it verified/ : /does not answer \(code 7\)|code 7/);
      noPassword(r.db.received(), `${method}: the server`);
      assert.equal(r.arbiter.decisionCalls.length, 0, `${method}: the gate is never asked (nothing to send)`);
    } finally { await r.close(); }
  }
});

test("the tripwire: a registered value sent raw where it is not bound is refused", async () => {
  const r = await rig({ method: "scram", user: "alice", password: REAL }, {
    fingerprintSecrets: [{ symbol: SYM, value: REAL, level: "no-model", bindings: ["other.db:5432"] }],
  });
  try {
    const res = await pgLogin(r.port, { user: "alice", password: REAL });
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /fingerprint tripwire/);
    assert.deepEqual(r.db.logins, []);
  } finally { await r.close(); }
});

test("TLS both sides: the client's sslmode=require gets the session CA's leaf for the database's name; the server's certificate is verified against the user's root certificate", { skip: !opensslAvailable() && "openssl unavailable" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-dbrelay-tls-"));
  try {
    const serverCa = ensureCa(join(dir, "server-ca"));
    const leaf = leafForHost(serverCa, "db.internal");
    const r = await rig(
      { method: "scram", user: "alice", password: REAL, tls: { key: leaf.keyPem, cert: leaf.certPem } },
      {},
      { mitm: { caDir: join(dir, "session-ca") }, dbUpstreamCa: readFileSync(serverCa.certPath, "utf8") },
    );
    try {
      const sessionCa = readFileSync(join(dir, "session-ca", "mandu-egress-ca.pem"), "utf8");
      const res = await pgLogin(r.port, { user: "alice", password: SYM, tls: { ca: sessionCa, servername: "db.internal" } });
      assert.equal(res.ok, true, res.error);
      assert.deepEqual(r.db.logins, [{ user: "alice", ok: true, tls: true }]);
    } finally { await r.close(); }

    // A server whose certificate does not chain to the user's root: refused.
    const other = ensureCa(join(dir, "other-ca"));
    const r2 = await rig(
      { method: "scram", user: "alice", password: REAL, tls: { key: leaf.keyPem, cert: leaf.certPem } },
      {},
      { dbUpstreamCa: readFileSync(other.certPath, "utf8") },
    );
    try {
      const res = await pgLogin(r2.port, { user: "alice", password: SYM });
      assert.equal(res.ok, false);
      assert.match(res.error ?? "", /TLS to db\.internal:5432 failed/);
      assert.deepEqual(r2.db.logins, []);
      assert.equal(r2.arbiter.decisionCalls.length, 0, "nothing was asked before the server was verified");
    } finally { await r2.close(); }

    // md5 is answered over TLS Mandu verified.
    const r3 = await rig(
      { method: "md5", user: "alice", password: REAL, tls: { key: leaf.keyPem, cert: leaf.certPem } },
      {},
      { dbUpstreamCa: readFileSync(serverCa.certPath, "utf8") },
    );
    try {
      const res = await pgLogin(r3.port, { user: "alice", password: SYM });
      assert.equal(res.ok, true, res.error);
      assert.deepEqual(r3.db.logins, [{ user: "alice", ok: true, tls: true }]);
      noPassword(r3.db.received(), "md5 never carries the password");
    } finally { await r3.close(); }

    // PGSSLROOTCERT=system: verified against the system store, which does
    // not hold this test's CA, so the TLS is refused (never unverified).
    const r4 = await rig(
      { method: "scram", user: "alice", password: REAL, tls: { key: leaf.keyPem, cert: leaf.certPem } },
      {},
      { dbUpstreamCa: "system" },
    );
    try {
      const res = await pgLogin(r4.port, { user: "alice", password: SYM });
      assert.equal(res.ok, false);
      assert.match(res.error ?? "", /TLS to db\.internal:5432 failed/);
    } finally { await r4.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("the client asks for TLS and the server offers none: refused", { skip: !opensslAvailable() && "openssl unavailable" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-dbrelay-notls-"));
  try {
    const r = await rig({ method: "scram", user: "alice", password: REAL }, {}, { mitm: { caDir: join(dir, "session-ca") } });
    try {
      const res = await pgLogin(r.port, { user: "alice", password: SYM, tls: {} });
      assert.equal(res.ok, false);
      assert.match(res.error ?? "", /does not offer TLS, and the client asked for it/);
    } finally { await r.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("without a session CA the client's SSLRequest is answered N (a plain loopback login still works)", async () => {
  const r = await rig({ method: "scram", user: "alice", password: REAL });
  try {
    const res = await pgLogin(r.port, { user: "alice", password: SYM, tls: {} });
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /answered "N" to SSLRequest/);
    const plain = await pgLogin(r.port, { user: "alice", password: SYM });
    assert.equal(plain.ok, true, plain.error);
  } finally { await r.close(); }
});
