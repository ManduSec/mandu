/**
 * db-login-release — the database login release over the REAL components
 * (docs/design/confidentiality/db-login-release.md): an ArbiterServer, the
 * launch HOME's `~/.pgpass` registered on the human socket as the launcher
 * does, and the REAL NetProxy's database relays in their production wiring
 * (`new ArbiterClientAdapter(new ArbiterClient(data), new ArbiterClient(human))`),
 * with fake Postgres servers that record every byte as the oracle.
 *
 *   1. the twin of `~/.pgpass` keeps each line and writes the placeholder
 *      escaped, so libpq reads it whole (`pgpassPassword`, libpq's rule);
 *   2. the placeholder logs in at its own database through the relay, by
 *      SCRAM-SHA-256 and by plain md5 (as psql would), the release resting
 *      on the file's own wire grant (no binding written by anyone); a `*`
 *      port line is bound to port 5432;
 *   3. the same placeholder at another database's relay is refused, and
 *      that server's method gets nothing;
 *   3b. the same placeholders over HTTP to the same hosts (any port) are
 *      refused (egress:secret-db-login-only, security review 2026-10-24):
 *      the grant is the relay's login only;
 *   4. THE ORACLE: neither the password nor the placeholder reaches any
 *      server (SCRAM never carries it), the client (the agent's
 *      world) never receives the password, and the twin (what a model
 *      reads) never holds it;
 *   5. the arbiter gone: the login is refused (fail-closed);
 *   6. MySQL the same way: a `~/.my.cnf` section's placeholder logs in at
 *      the database it names (mysql_native_password, caching_sha2_password),
 *      never at another;
 *   7. `PGPASSWORD` with `PGHOST` / `PGPORT`, and `MYSQL_PWD` with
 *      `MYSQL_HOST` / `MYSQL_TCP_PORT`, in the launch environment (registered
 *      as the launcher does): bound to exactly that host and port with no
 *      binding of anyone's (2026-10-25), so each logs in with no Approvals
 *      card; at another host, another port, the other's login, over HTTP,
 *      or after a launch without the host variable: refused.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { pgpassPassword } from "../../arbiter/policy/secret-extract.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { MockSites } from "../../interceptors/net-proxy/src/mock-sites.js";
import { pgLogin, startFakePostgres } from "../../interceptors/net-proxy/test/fake-postgres.js";
import { mysqlLogin, startFakeMysql } from "../../interceptors/net-proxy/test/fake-mysql.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const PW_SCRAM = "pgScramPW_DBLOGIN:9x";
const PW_MD5 = "pgBobPW_DBLOGIN_4k";
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYDBLOGINKEY";
const RDS = "prod.abc123.us-east-1.rds.amazonaws.com";

/** A plain-HTTP request through the egress proxy: its status and body. */
function viaProxy(port: number, url: string, authorization: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "GET", path: url, headers: { host: u.host, authorization } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    r.on("error", reject);
    r.end();
  });
}

test(
  "a ~/.pgpass placeholder logs in at its own database through the relay, never at another and never over HTTP; no server, client or twin ever holds the password",
  { timeout: 60_000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-db-login-"));
    const home = join(dir, "home");
    mkdirSync(home, { recursive: true });
    const pgpass = join(home, ".pgpass");
    // An AWS key in the same HOME: its placeholder must never log in to a
    // database, an `*.rds.amazonaws.com` one included.
    mkdirSync(join(home, ".aws"), { recursive: true });
    const awsCreds = join(home, ".aws", "credentials");
    writeFileSync(awsCreds, `[default]\naws_access_key_id = AKIDEXAMPLE\naws_secret_access_key = ${AWS_SECRET}\n`, { mode: 0o600 });
    // The SCRAM password holds a colon, escaped as libpq wants it.
    writeFileSync(pgpass, `db.internal:5432:app:alice:${PW_SCRAM.replace(":", "\\:")}\nold.internal:*:*:bob:${PW_MD5}\n`, { mode: 0o600 });
    const sock = join(dir, "arbiter.sock");
    const humanSock = join(dir, "human", "h.sock");
    const server = new ArbiterServer({
      socketPath: sock, humanSocketPath: humanSock, adminSocketPath: join(dir, "admin.sock"),
      dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), log: () => {},
      adminPolicyDir: null, packDir: null, confidentiality: true, integrity: false,
      // The file is labelled with no bindings: every release below rests on
      // the registration's wire grant alone.
      policyDocument: { version: 1, paths: [{ path: pgpass, level: "no-model" }, { path: awsCreds, level: "no-model" }] },
    });
    await server.listen();
    const data = new ArbiterClient(sock); await data.connect();
    const human = new ArbiterClient(humanSock); await human.connect();
    const scramDb = await startFakePostgres({ method: "scram", user: "alice", password: PW_SCRAM });
    const md5Db = await startFakePostgres({ method: "md5", user: "bob", password: PW_MD5 });
    // An HTTP listener the db hosts are routed to: what a curl to them gets.
    const httpGot: string[] = [];
    const web = createServer((req, res) => { httpGot.push(JSON.stringify(req.headers) + req.url); res.end("ok"); });
    web.listen(0, "127.0.0.1");
    await once(web, "listening");
    const webPort = (web.address() as AddressInfo).port;
    const decoy = await startFakePostgres({ method: "scram", user: "alice", password: PW_SCRAM });
    const rds = await startFakePostgres({ method: "scram", user: "alice", password: AWS_SECRET });
    const proxy = new NetProxy({
      log: () => {}, sessionId: "sess-db-login",
      arbiter: new NetProxyAdapter(data as unknown as NetProxyRealClient, human as never),
      attributeHolders: () => [{ procKey: "7100-1", ancestors: [] }],
      allowThisMachine: true,
      mockSites: MockSites.fromYaml(["hosts:", ...["db.internal", "old.internal", "evil.old.internal"].flatMap((h) => [`  - host: "${h}"`, `    to: 127.0.0.1:${webPort}`]), ""].join("\n")),
      // The fake servers are this test's own: told apart from the session's.
      dbLocalServer: () => "other",
      dbRelays: [
        { protocol: "postgres", host: "db.internal", port: 5432 },
        { protocol: "postgres", host: "old.internal", port: 5432 },
        { protocol: "postgres", host: "evil.example", port: 5432 },
        { protocol: "postgres", host: RDS, port: 5432 },
      ],
      dbRoutes: new Map([
        ["db.internal:5432", { host: "127.0.0.1", port: scramDb.port }],
        ["old.internal:5432", { host: "127.0.0.1", port: md5Db.port }],
        ["evil.example:5432", { host: "127.0.0.1", port: decoy.port }],
        [`${RDS}:5432`, { host: "127.0.0.1", port: rds.port }],
      ]),
    });
    let arbiterUp = true;
    try {
      const proxyPort = await proxy.listen(0);
      const relays = new Map((await proxy.listenDbRelays()).map((r) => [r.host, r.listen]));

      // 1. Registered as the launcher does: the HOME file, on the human socket.
      const reg = await human.registerSecret({ path: pgpass, home, sessionKey: "sess-db-login" });
      assert.ok(reg.twin, reg.reason);
      for (const pw of [PW_SCRAM, PW_MD5, PW_SCRAM.replace(":", "\\:")]) assert.ok(!reg.twin!.includes(pw), "the twin holds no password");
      const lines = reg.twin!.trim().split("\n");
      assert.match(lines[0]!, /^db\.internal:5432:app:alice:\$MDU\\:/, "the line kept, the token's colon escaped");
      // What libpq reads from the twin: the whole placeholder.
      const [alicePh, bobPh] = lines.map((l) => pgpassPassword(l.split(/(?<!\\):/).slice(4).join(":")));
      for (const ph of [alicePh, bobPh]) assert.match(ph!, /^\$MDU:[a-zA-Z_]+\[[0-9a-f]+\]\.[a-z]+\.password$/, ph);

      // 2. Each placeholder logs in at its own database.
      const a = await pgLogin(relays.get("db.internal")!, { user: "alice", password: alicePh!, database: "app" });
      assert.equal(a.ok, true, a.error);
      assert.equal(a.tag, "ECHO SELECT 1");
      const b = await pgLogin(relays.get("old.internal")!, { user: "bob", password: bobPh! });
      assert.equal(b.ok, true, b.error);
      assert.deepEqual([scramDb.logins, md5Db.logins], [[{ user: "alice", ok: true, tls: false }], [{ user: "bob", ok: true, tls: false }]]);

      // 3. At another database (and each at the other's): refused, nothing sent.
      const e = await pgLogin(relays.get("evil.example")!, { user: "alice", password: alicePh! });
      assert.equal(e.ok, false);
      assert.match(e.error ?? "", /was not put back/);
      const crossed = await pgLogin(relays.get("old.internal")!, { user: "bob", password: alicePh! });
      assert.equal(crossed.ok, false, "alice's password at bob's database");
      assert.deepEqual(decoy.logins, [], "the decoy saw no login");
      assert.equal(md5Db.logins.length, 1, "nothing more reached bob's database");

      // 3b. The same placeholders over HTTP to their own hosts, any port, and
      //     under the `*` line's host: refused, nothing reaches the listener.
      for (const [ph, url] of [
        [alicePh!, "http://db.internal:5432/x"],
        [bobPh!, "http://old.internal:5432/x"],
        [bobPh!, "http://old.internal/x"],
        [bobPh!, "http://old.internal:8080/x"],
        [bobPh!, "http://evil.old.internal:5432/x"],
      ] as const) {
        const r = await viaProxy(proxyPort, url, ph);
        assert.equal(r.status, 403, `${url}: ${r.body}`);
      }
      const atOwn = await viaProxy(proxyPort, "http://db.internal:5432/x", alicePh!);
      assert.match(atOwn.body, /egress:secret-db-login-only/, "the rule that refused it at its own database's address");
      // As the key an AWS request is re-signed with (aws-sigv4-resign.md's
      // `signature` position), over HTTPS: the same hard refusal.
      for (const destination of ["db.internal:5432", "s3.amazonaws.com"]) {
        const asKey = await human.desymbolizationDecision({ symbol: alicePh!, boundary: "network", destination, asCommand: false, scheme: "https", positions: ["signature"], sessionKey: "sess-db-login" });
        assert.equal(asKey.allow, false, destination);
        if (destination === "db.internal:5432") assert.equal(asKey.ruleRef?.id, "egress:secret-db-login-only");
      }
      assert.deepEqual(httpGot, [], "no HTTP request carrying a placeholder or a password left");

      // 3c. The AWS key's placeholder as the password of a Postgres login to
      //     an `*.rds.amazonaws.com` relay target: refused, nothing reaches it
      //     (the AWS grant is HTTPS only; a SigV4 check never reads a
      //     `postgres` request as HTTPS).
      const awsReg = await human.registerSecret({ path: awsCreds, home, sessionKey: "sess-db-login" });
      const awsPh = /aws_secret_access_key = (\S+)/.exec(awsReg.twin ?? "")?.[1];
      assert.match(awsPh ?? "", /^\$MDU:/, awsReg.twin);
      const viaRds = await pgLogin(relays.get(RDS)!, { user: "alice", password: awsPh! });
      assert.equal(viaRds.ok, false);
      assert.match(viaRds.error ?? "", /was not put back/);
      assert.deepEqual(rds.logins, [], "no login reached the RDS-named database");
      assert.ok(!rds.received().toString("latin1").includes(AWS_SECRET), "the AWS key never on the database wire");

      // 4. THE ORACLE.
      for (const [name, db] of [["alice's", scramDb], ["bob's", md5Db], ["decoy", decoy]] as const) {
        const got = db.received().toString("latin1");
        for (const pw of [PW_SCRAM, PW_MD5]) assert.ok(!got.includes(pw), `${name}: no password on the wire`);
        assert.ok(!got.includes("$MDU:"), `${name}: no placeholder on the wire`);
      }
      for (const r of [a, b, e, crossed]) {
        const got = r.received.toString("latin1");
        for (const pw of [PW_SCRAM, PW_MD5]) assert.ok(!got.includes(pw), "the client never receives a password");
      }

      // 5. The arbiter gone: refused, fail-closed.
      data.close();
      human.close();
      await server.close();
      arbiterUp = false;
      const down = await pgLogin(relays.get("db.internal")!, { user: "alice", password: alicePh! });
      assert.equal(down.ok, false);
      assert.equal(scramDb.logins.length, 1, "no login reached the server with the arbiter gone");
    } finally {
      await proxy.close();
      for (const db of [scramDb, md5Db, decoy, rds]) await db.close();
      web.close();
      if (arbiterUp) {
        data.close();
        human.close();
        await server.close();
      }
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

const MY_NATIVE = "myNativePW_DBLOGIN_2j";
const MY_SHA2 = "mySha2PW_DBLOGIN_6p";

test(
  "a ~/.my.cnf placeholder logs in at its own MySQL database through the relay (native and caching_sha2), never at another; no server or client ever holds the password",
  { timeout: 60_000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-db-login-my-"));
    const home = join(dir, "home");
    mkdirSync(home, { recursive: true });
    const mycnf = join(home, ".my.cnf");
    writeFileSync(mycnf, `[client]\nuser=alice\npassword=${MY_NATIVE}\nhost=mysql.internal\n\n[mysqldump]\nuser=bob\npassword=${MY_SHA2}\nhost=dump.internal\nport=3307\n`, { mode: 0o600 });
    const sock = join(dir, "arbiter.sock");
    const humanSock = join(dir, "human", "h.sock");
    const server = new ArbiterServer({
      socketPath: sock, humanSocketPath: humanSock, adminSocketPath: join(dir, "admin.sock"),
      dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), log: () => {},
      adminPolicyDir: null, packDir: null, confidentiality: true, integrity: false,
      policyDocument: { version: 1, paths: [{ path: mycnf, level: "no-model" }] },
    });
    await server.listen();
    const data = new ArbiterClient(sock); await data.connect();
    const human = new ArbiterClient(humanSock); await human.connect();
    const nativeDb = await startFakeMysql({ plugin: "native", user: "alice", password: MY_NATIVE });
    const sha2Db = await startFakeMysql({ plugin: "caching_sha2", user: "bob", password: MY_SHA2, cached: true });
    const decoy = await startFakeMysql({ plugin: "native", user: "alice", password: MY_NATIVE });
    const httpGot: string[] = [];
    const web = createServer((req, res) => { httpGot.push(JSON.stringify(req.headers) + req.url); res.end("ok"); });
    web.listen(0, "127.0.0.1");
    await once(web, "listening");
    const webPort = (web.address() as AddressInfo).port;
    const proxy = new NetProxy({
      log: () => {}, sessionId: "sess-db-login-my",
      arbiter: new NetProxyAdapter(data as unknown as NetProxyRealClient, human as never),
      attributeHolders: () => [{ procKey: "7200-1", ancestors: [] }],
      allowThisMachine: true,
      mockSites: MockSites.fromYaml(["hosts:", ...["mysql.internal", "dump.internal"].flatMap((h) => [`  - host: "${h}"`, `    to: 127.0.0.1:${webPort}`]), ""].join("\n")),
      dbLocalServer: () => "other",
      dbRelays: [
        { protocol: "mysql", host: "mysql.internal", port: 3306 },
        { protocol: "mysql", host: "dump.internal", port: 3307 },
        { protocol: "mysql", host: "evil.example", port: 3306 },
      ],
      dbRoutes: new Map([
        ["mysql.internal:3306", { host: "127.0.0.1", port: nativeDb.port }],
        ["dump.internal:3307", { host: "127.0.0.1", port: sha2Db.port }],
        ["evil.example:3306", { host: "127.0.0.1", port: decoy.port }],
      ]),
    });
    try {
      const proxyPort = await proxy.listen(0);
      const relays = new Map((await proxy.listenDbRelays()).map((r) => [r.host, r.listen]));
      const reg = await human.registerSecret({ path: mycnf, home, sessionKey: "sess-db-login-my" });
      assert.ok(reg.twin, reg.reason);
      for (const pw of [MY_NATIVE, MY_SHA2]) assert.ok(!reg.twin!.includes(pw), "the twin holds no password");
      const [alicePh, bobPh] = [...reg.twin!.matchAll(/^password=(.+)$/gm)].map((m) => m[1]!);
      for (const ph of [alicePh, bobPh]) assert.match(ph!, /^\$MDU:[a-zA-Z_]+\[[0-9a-f]+\]\.[a-z]+\.password$/, ph);

      const a = await mysqlLogin(relays.get("mysql.internal")!, { user: "alice", password: alicePh!, publicKey: true });
      assert.equal(a.ok, true, a.error);
      assert.equal(a.info, "ECHO SELECT 1");
      const b = await mysqlLogin(relays.get("dump.internal")!, { user: "bob", password: bobPh!, publicKey: true });
      assert.equal(b.ok, true, b.error);
      const e = await mysqlLogin(relays.get("evil.example")!, { user: "alice", password: alicePh!, publicKey: true });
      assert.equal(e.ok, false);
      assert.match(e.error ?? "", /was not put back/);
      const crossed = await mysqlLogin(relays.get("dump.internal")!, { user: "bob", password: alicePh!, publicKey: true });
      assert.equal(crossed.ok, false, "alice's password at bob's database");
      assert.deepEqual(decoy.logins, [], "the decoy saw no login");
      assert.deepEqual([nativeDb.logins.length, sha2Db.logins.length], [1, 1]);

      // Over HTTP to the sections' own hosts and ports: refused
      // (egress:secret-db-login-only), nothing leaves.
      for (const [ph, url] of [[alicePh!, "http://mysql.internal:3306/x"], [bobPh!, "http://dump.internal:3307/x"], [bobPh!, "http://dump.internal/x"]] as const) {
        const r = await viaProxy(proxyPort, url, ph);
        assert.equal(r.status, 403, `${url}: ${r.body}`);
        assert.match(r.body, /egress:secret-db-login-only|not bound/, url);
      }
      assert.deepEqual(httpGot, [], "no HTTP request carrying a placeholder or a password left");

      for (const [name, db] of [["native", nativeDb], ["sha2", sha2Db], ["decoy", decoy]] as const) {
        const got = db.received().toString("latin1");
        for (const pw of [MY_NATIVE, MY_SHA2]) assert.ok(!got.includes(pw), `${name}: no password on the wire`);
        assert.ok(!got.includes("$MDU:"), `${name}: no placeholder on the wire`);
      }
      for (const r of [a, b, e, crossed]) for (const pw of [MY_NATIVE, MY_SHA2]) assert.ok(!r.received.toString("latin1").includes(pw), "the client never receives a password");
    } finally {
      await proxy.close();
      for (const db of [nativeDb, sha2Db, decoy]) await db.close();
      web.close();
      data.close();
      human.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

const ENV_PG_PW = "pgEnvPW_DBLOGIN_8m";
const ENV_MY_PW = "myEnvPW_DBLOGIN_5w";

test(
  "PGPASSWORD + PGHOST and MYSQL_PWD + MYSQL_HOST log in through the relay with no prompt, bound to exactly that host and port; anywhere else, over HTTP, or launched without the host variable: refused",
  { timeout: 60_000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-db-login-env-"));
    const sock = join(dir, "arbiter.sock");
    const humanSock = join(dir, "human", "h.sock");
    // No policy binds either variable: every release below rests on the
    // automatic binding to the host variable beside it (db-login-release.md
    // §3.3, 2026-10-25).
    const server = new ArbiterServer({
      socketPath: sock, humanSocketPath: humanSock, adminSocketPath: join(dir, "admin.sock"),
      dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), log: () => {},
      adminPolicyDir: null, packDir: null, confidentiality: true, integrity: false,
      policyDocument: { version: 1 },
    });
    await server.listen();
    const data = new ArbiterClient(sock); await data.connect();
    const human = new ArbiterClient(humanSock); await human.connect();
    const pgDb = await startFakePostgres({ method: "scram", user: "app", password: ENV_PG_PW });
    const pgElsewhere = await startFakePostgres({ method: "scram", user: "app", password: ENV_PG_PW });
    const pgOtherPort = await startFakePostgres({ method: "md5", user: "app", password: ENV_PG_PW });
    const myDb = await startFakeMysql({ plugin: "native", user: "app", password: ENV_MY_PW });
    const myDecoy = await startFakeMysql({ plugin: "native", user: "app", password: ENV_MY_PW });
    const httpGot: string[] = [];
    const web = createServer((req, res) => { httpGot.push(JSON.stringify(req.headers) + req.url); res.end("ok"); });
    web.listen(0, "127.0.0.1");
    await once(web, "listening");
    const webPort = (web.address() as AddressInfo).port;
    const proxy = new NetProxy({
      log: () => {}, sessionId: "sess-db-login-env",
      arbiter: new NetProxyAdapter(data as unknown as NetProxyRealClient, human as never),
      attributeHolders: () => [{ procKey: "7300-1", ancestors: [] }],
      allowThisMachine: true,
      mockSites: MockSites.fromYaml(["hosts:", ...["pg.env.internal", "mysql.env.internal"].flatMap((h) => [`  - host: "${h}"`, `    to: 127.0.0.1:${webPort}`]), ""].join("\n")),
      dbLocalServer: () => "other",
      // The relays the launcher opens for this environment (db-relays.ts
      // pgEnvTargets / mysqlEnvTargets), and decoys a program could aim at.
      dbRelays: [
        { protocol: "postgres", host: "pg.env.internal", port: 6543 },
        { protocol: "postgres", host: "pg.env.internal", port: 5432 },
        { protocol: "postgres", host: "evil.example", port: 6543 },
        { protocol: "mysql", host: "mysql.env.internal", port: 3307 },
        { protocol: "mysql", host: "evil.example", port: 3307 },
      ],
      dbRoutes: new Map([
        ["pg.env.internal:6543", { host: "127.0.0.1", port: pgDb.port }],
        ["pg.env.internal:5432", { host: "127.0.0.1", port: pgOtherPort.port }],
        ["evil.example:6543", { host: "127.0.0.1", port: pgElsewhere.port }],
        ["mysql.env.internal:3307", { host: "127.0.0.1", port: myDb.port }],
        ["evil.example:3307", { host: "127.0.0.1", port: myDecoy.port }],
      ]),
    });
    try {
      const proxyPort = await proxy.listen(0);
      const relays = new Map((await proxy.listenDbRelays()).map((r) => [`${r.protocol}:${r.host}:${r.port}`, r.listen]));

      // Registered as the launcher does (secret-setup.ts applyEnvSecrets):
      // every variable of the launch environment, on the human socket, with
      // no session key (so a later launch reuses the row).
      const launch = {
        PGPASSWORD: ENV_PG_PW, PGHOST: "pg.env.internal", PGPORT: "6543", PGUSER: "app",
        MYSQL_PWD: ENV_MY_PW, MYSQL_HOST: "mysql.env.internal", MYSQL_TCP_PORT: "3307",
      };
      const reg = await human.registerEnvSecrets({ vars: Object.entries(launch).map(([name, value]) => ({ name, value })) });
      const byName = new Map(reg.vars.map((v) => [v.name, v]));
      const pgPh = byName.get("PGPASSWORD")?.twin;
      const myPh = byName.get("MYSQL_PWD")?.twin;
      assert.match(pgPh ?? "", /^\$MDU:[a-zA-Z_]+\[[0-9a-f]+\]\.PGPASSWORD$/, JSON.stringify(reg));
      assert.match(myPh ?? "", /^\$MDU:[a-zA-Z_]+\[[0-9a-f]+\]\.MYSQL_PWD$/, JSON.stringify(reg));
      for (const name of ["PGHOST", "PGPORT", "MYSQL_HOST", "MYSQL_TCP_PORT"]) assert.equal(byName.get(name)?.symbol, null, `${name} stays as it is`);

      // 1. Each logs in at its own database through the relay, no prompt.
      const pg = await pgLogin(relays.get("postgres:pg.env.internal:6543")!, { user: "app", password: pgPh!, database: "app" });
      assert.equal(pg.ok, true, pg.error);
      const my = await mysqlLogin(relays.get("mysql:mysql.env.internal:3307")!, { user: "app", password: myPh!, publicKey: true });
      assert.equal(my.ok, true, my.error);
      assert.deepEqual([pgDb.logins, myDb.logins.length], [[{ user: "app", ok: true, tls: false }], 1]);
      assert.deepEqual(await human.egressApprovals("pending"), [], "no Approvals card: the binding released it");

      // 2. Another host, or the same host at another port: refused, nothing
      //    reaches that server's method.
      for (const key of ["postgres:evil.example:6543", "postgres:pg.env.internal:5432"]) {
        const r = await pgLogin(relays.get(key)!, { user: "app", password: pgPh! });
        assert.equal(r.ok, false, key);
        assert.match(r.error ?? "", /was not put back/, key);
      }
      const myElsewhere = await mysqlLogin(relays.get("mysql:evil.example:3307")!, { user: "app", password: myPh!, publicKey: true });
      assert.equal(myElsewhere.ok, false);
      assert.match(myElsewhere.error ?? "", /was not put back/);
      // Each password in the other's login: refused (its own scheme only).
      const crossed = await pgLogin(relays.get("postgres:pg.env.internal:6543")!, { user: "app", password: myPh! });
      assert.equal(crossed.ok, false, "MYSQL_PWD in a Postgres login");
      assert.deepEqual([pgElsewhere.logins, pgOtherPort.logins, myDecoy.logins], [[], [], []], "no decoy saw a login");
      assert.equal(pgDb.logins.length, 1, "nothing more reached the bound database");

      // 3. Over HTTP to the bound host and port, or the host alone: hard
      //    refused (egress:secret-db-login-only), nothing leaves.
      for (const [ph, url] of [[pgPh!, "http://pg.env.internal:6543/x"], [pgPh!, "http://pg.env.internal/x"], [myPh!, "http://mysql.env.internal:3307/x"]] as const) {
        const r = await viaProxy(proxyPort, url, ph);
        assert.equal(r.status, 403, `${url}: ${r.body}`);
      }
      assert.match((await viaProxy(proxyPort, "http://pg.env.internal:6543/x", pgPh!)).body, /egress:secret-db-login-only/);
      assert.deepEqual(httpGot, [], "no HTTP request carrying a placeholder or a password left");

      // 4. THE ORACLE: no password at any server's wire (SCRAM and the
      //    native answer never carry it), no placeholder there, none at the
      //    client.
      for (const [name, db] of [["pg", pgDb], ["pg elsewhere", pgElsewhere], ["pg other port", pgOtherPort], ["mysql", myDb], ["mysql decoy", myDecoy]] as const) {
        const got = db.received().toString("latin1");
        for (const pw of [ENV_PG_PW, ENV_MY_PW]) assert.ok(!got.includes(pw), `${name}: no password on the wire`);
        assert.ok(!got.includes("$MDU:"), `${name}: no placeholder on the wire`);
      }
      for (const r of [pg, my, myElsewhere, crossed]) for (const pw of [ENV_PG_PW, ENV_MY_PW]) assert.ok(!r.received.toString("latin1").includes(pw), "the client never receives a password");

      // 5. A later launch with the same password but no PGHOST (libpq's
      //    socket): the earlier host is not kept, so the login asks again.
      const again = await human.registerEnvSecrets({ vars: [{ name: "PGPASSWORD", value: ENV_PG_PW }, { name: "PGUSER", value: "app" }] });
      assert.equal(again.vars[0]?.twin, pgPh, "the same row");
      const unbound = await pgLogin(relays.get("postgres:pg.env.internal:6543")!, { user: "app", password: pgPh! });
      assert.equal(unbound.ok, false);
      assert.match(unbound.error ?? "", /was not put back/);
      assert.equal(pgDb.logins.length, 1, "no login reached the database once the host variable was gone");
    } finally {
      await proxy.close();
      for (const db of [pgDb, pgElsewhere, pgOtherPort]) await db.close();
      for (const db of [myDb, myDecoy]) await db.close();
      web.close();
      data.close();
      human.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
