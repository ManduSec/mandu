/**
 * live-db-clients — the database login release (docs/design/confidentiality/
 * db-login-release.md) measured with the REAL clients against REAL servers
 * under a launched session (docs/design/testing/live-clients.md §2): until
 * now its tests used the fake servers of interceptors/net-proxy/test/.
 *
 * Two "machines" with no root (tests/lib/netns.ts): this side runs the real
 * launcher in `secrets` around the stand-in `claude` (its Bash tool runs the
 * real `psql` and `mysql`; tests/lib/live-clients.ts), and the other machine
 * (10.77.0.2, and 203.0.113.9 outside the network) runs a real PostgreSQL
 * twice (TLS with the suite's CA: alice by SCRAM-SHA-256, bob by md5; no
 * TLS: carol), a real MySQL 8 (TLS: alice mysql_native_password, bob
 * caching_sha2_password with the server's cache warm, dave with it cold) and
 * decoys that record what they get (fixtures/live-db-peer.fixture.ts). The
 * launch HOME holds `~/.pgpass`, `~/.postgresql/root.crt` and `~/.my.cnf`
 * with the real passwords, as a user keeps them: discovery and the files'
 * own wire grants do the rest; nothing is labelled or bound by hand.
 *
 * Asserted, per case (lib/live-db.ts pgCases / myCases): the client logs in
 * at the database its file names, by each method and TLS setting, and is
 * refused where the placeholder is not bound; and for every launch, THE
 * ORACLE: no password (in any of secretForms' spellings) in any request the
 * model received, in what the agent's world saw (each case's output), in the
 * session's events or in the launch's output; none at a decoy (the
 * decoys know the real password: a login that succeeds there is a leak, and
 * each decoy must have been reached, so the check is not vacuous); the HOME
 * files unchanged.
 *
 * Self-SKIPs where the topology cannot be built (no unprivileged user and
 * network namespaces), the guard is not built, or the servers and clients
 * are not installed (the CI image has them: scripts/ci/guest/provision.sh).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runTwoHostNet, twoHostNetUnavailable } from "../../lib/netns.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";
import { caseExit, secretForms, type LiveLaunch, type LiveLaunchResult } from "../../lib/live-clients.js";
import { envCases, LIVE_DB_ADDR, LIVE_DB_HOSTS, liveDbBins, livePassword, myCases, myCasesWithCa, pgCases, type LiveDbConfig } from "../../lib/live-db.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../../interceptors/net-proxy/src/ca.js";

stateAxes("secrets"); // the confidentiality axis: a password never reaches a model or an unbound host

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = join(HERE, "..", ".."); // tests/
const TSX = join(PKG_ROOT, "node_modules", ".bin", "tsx");
const GUARD = pickGuard(resolve(PKG_ROOT, "..", "interceptors", "target"));
const BINS = process.platform === "linux" ? liveDbBins() : "Linux only";
const skip = process.platform !== "linux" ? "Linux only"
  : twoHostNetUnavailable()
  ?? (!GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
    : typeof BINS === "string" ? BINS
      : !opensslAvailable() ? "no openssl (the suite's certificates)"
        : false);

/** The pid files the peer's servers write: killed after the run, whatever happened. */
function killServers(dir: string): void {
  for (const f of [join(dir, "pg1", "postmaster.pid"), join(dir, "pg2", "postmaster.pid"), join(dir, "mysqld.pid")]) {
    if (!existsSync(f)) continue;
    const pid = Number(readFileSync(f, "utf8").split("\n")[0]);
    if (Number.isInteger(pid) && pid > 1) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } }
  }
}

const escPgpass = (s: string): string => s.replace(/\\/g, "\\\\").replace(/:/g, "\\:");

test("the real psql and mysql log in from the launch HOME's files through the relay, and no password reaches the model, the agent's world or an unbound host", { skip, timeout: 1_500_000 }, async () => {
  const bins = BINS as Exclude<typeof BINS, string>;
  const dir = mkdtempSync(join(tmpdir(), "mdu-ldb-"));
  assert.ok(Buffer.byteLength(join(dir, "s", ".s.PGSQL.5432.lock")) < 100, `the socket dir is short enough: ${dir}`);
  let keep = false;
  try {
    // ── the certificates: the suite's CA, a leaf per server name ─────────
    const ca = ensureCa(join(dir, "ca"));
    const certs = { ca: ca.certPath, pgCert: join(dir, "pg.crt"), pgKey: join(dir, "pg.key"), myCert: join(dir, "my.crt"), myKey: join(dir, "my.key") };
    for (const [host, cert, key] of [[LIVE_DB_HOSTS.pg, certs.pgCert, certs.pgKey], [LIVE_DB_HOSTS.my, certs.myCert, certs.myKey]] as const) {
      const leaf = leafForHost(ca, host);
      writeFileSync(cert, leaf.certPem, { mode: 0o644 });
      writeFileSync(key, leaf.keyPem, { mode: 0o600 });
    }
    const cfg: LiveDbConfig = {
      dir, uid: process.getuid!(), gid: process.getgid!(), bins, ...LIVE_DB_ADDR,
      // alice's holds a colon: the twin escapes it, as libpq reads it.
      pg: { port: 5432, port2: 5433, alice: livePassword("pgA", ":"), bob: livePassword("pgB"), carol: livePassword("pgC") },
      my: { port: 3306, evePort: 3307, alice: livePassword("myA"), bob: livePassword("myB"), dave: livePassword("myD"), eve: livePassword("myE") },
      certs, ready: join(dir, "peer.ready"), decoyLog: join(dir, "decoys.json"), peerLog: join(dir, "peer.log"),
    };
    const configPath = join(dir, "config.json");
    writeFileSync(configPath, JSON.stringify(cfg), { mode: 0o600 });
    writeFileSync(cfg.peerLog, "");
    const secrets: Record<string, string> = {
      "pg alice": cfg.pg.alice, "pg bob": cfg.pg.bob, "pg carol": cfg.pg.carol,
      "my alice": cfg.my.alice, "my bob": cfg.my.bob, "my dave": cfg.my.dave, "my eve": cfg.my.eve,
    };

    // ── the launch HOME's files, as a user keeps them ─────────────────────
    const pgpass = [
      `${LIVE_DB_HOSTS.pg}:5432:*:alice:${escPgpass(cfg.pg.alice)}`,
      `${LIVE_DB_HOSTS.pg}:5432:*:bob:${escPgpass(cfg.pg.bob)}`,
      `${cfg.addr}:${cfg.pg.port2}:*:carol:${escPgpass(cfg.pg.carol)}`,
      `${LIVE_DB_HOSTS.pg2}:${cfg.pg.port2}:*:carol:${escPgpass(cfg.pg.carol)}`,
      "",
    ].join("\n");
    const mycnf = (clientExtra: string[]): string => [
      "[client]", "user=alice", `password=${cfg.my.alice}`, `host=${LIVE_DB_HOSTS.my}`, ...clientExtra, "",
      "[client_bob]", "user=bob", `password=${cfg.my.bob}`, "",
      "[client_dave]", "user=dave", `password=${cfg.my.dave}`, "",
      "[client_eve]", "user=eve", `password=${cfg.my.eve}`, `host=${cfg.addr}`, `port=${cfg.my.evePort}`, "",
    ].join("\n");
    const caPem = readFileSync(ca.certPath, "utf8");
    const launches: LiveLaunch[] = [
      {
        name: "main",
        files: { ".pgpass": pgpass, ".postgresql/root.crt": caPem, ".my.cnf": mycnf([]) },
        cases: [...pgCases(cfg.addr, cfg.outside, cfg.pg.port2), ...myCases(cfg.outside)],
      },
      {
        // [client] names the server's CA: the relay verifies the server, so
        // dave's first login (caching_sha2's full path) can be served.
        name: "mycnf-ssl-ca",
        files: { ".my.cnf": mycnf([`ssl-ca=${certs.ca}`]) },
        cases: myCasesWithCa(),
      },
      {
        // The variables (db-login-release.md §3.3.1): no password file, the
        // passwords in the launch's environment beside their hosts.
        name: "env-vars",
        files: { ".postgresql/root.crt": caPem },
        env: { PGPASSWORD: cfg.pg.alice, PGHOST: LIVE_DB_HOSTS.pg, MYSQL_PWD: cfg.my.alice, MYSQL_HOST: LIVE_DB_HOSTS.my },
        cases: envCases(),
      },
    ];
    const scenarioPath = join(dir, "scenario.json");
    const resultPath = join(dir, "result.json");
    writeFileSync(scenarioPath, JSON.stringify({ scratch: join(dir, "scratch"), result: resultPath, launches }), { mode: 0o600 });

    const r = await runTwoHostNet({
      hosts: { [LIVE_DB_HOSTS.pg]: [cfg.addr], [LIVE_DB_HOSTS.pg2]: [cfg.outside], [LIVE_DB_HOSTS.my]: [cfg.addr] },
      peer: [TSX, join(PKG_ROOT, "fixtures", "live-db-peer.fixture.ts")],
      peerReady: cfg.ready,
      main: [TSX, join(PKG_ROOT, "fixtures", "live-db-scenario.fixture.ts")],
      env: { ...process.env, LIVE_DB_CONFIG: configPath, LIVE_DB_SCENARIO: scenarioPath },
      timeoutMs: 1_400_000,
    });
    killServers(dir);
    const peerLog = existsSync(cfg.peerLog) ? readFileSync(cfg.peerLog, "utf8") : "";
    const last = r.stdout.trim().split("\n").pop() ?? "";
    let out: { launches?: LiveLaunchResult[]; error?: string; result?: string };
    try {
      out = JSON.parse(last) as typeof out;
      if (out.result) out = JSON.parse(readFileSync(out.result, "utf8")) as typeof out;
    } catch {
      keep = true;
      assert.fail(`the scenario printed no result (exit ${r.status}):\n${r.stderr.slice(-6000)}\n${r.stdout.slice(-3000)}\n--- peer ---\n${peerLog.slice(-4000)}`);
    }
    if (out.error) { keep = true; assert.fail(`the scenario failed: ${out.error}\n--- peer ---\n${peerLog.slice(-4000)}`); }
    const decoys = JSON.parse(readFileSync(cfg.decoyLog, "utf8")) as Record<string, { logins: Array<{ user: string; ok: boolean }>; connections: number; received: string }>;

    for (const l of out.launches!) {
      // The evidence, in the log of every run (green or red).
      for (const [name, text] of Object.entries(l.cases)) console.error(`live-db-clients ${l.name} ${name}: exit=${caseExit(text)} ${text.trim().split("\n").slice(0, 2).join(" | ").slice(0, 300)}`);
    }
    for (const [k, d] of Object.entries(decoys)) console.error(`live-db-clients decoy ${k}: ${d.connections} connection(s), logins ${JSON.stringify(d.logins)}`);

    const main = out.launches!.find((l) => l.name === "main")!;
    const diag = (l: LiveLaunchResult): string => `\n--- launch ${l.name} (exit ${l.code}) ---\n${l.outTail.slice(-5000)}\n--- cases ---\n${Object.entries(l.cases).map(([k, v]) => `[${k}]\n${v}`).join("\n")}\n--- peer ---\n${peerLog.slice(-2000)}`;
    keep = true; // until every assertion below holds
    assert.equal(main.code, 0, `the launch failed${diag(main)}`);
    assert.ok(main.guardLive, `the guard did not engage (the relay's redirect needs it)${diag(main)}`);
    assert.match(main.outTail, /database logins go through Mandu's relay/, `the launch opened the database relays${diag(main)}`);

    // ── each case ──────────────────────────────────────────────────────────
    const c = main.cases;
    const ok = (name: string, re: RegExp): void => {
      assert.equal(caseExit(c[name]!), 0, `${name} failed${diag(main)}`);
      assert.match(c[name]!, re, `${name}${diag(main)}`);
    };
    const refused = (name: string, re: RegExp): void => {
      assert.notEqual(caseExit(c[name]!), 0, `${name} was not refused${diag(main)}`);
      assert.match(c[name]!, re, `${name}${diag(main)}`);
    };
    assert.match(c["pg-twin"]!, /\$MDU\\:/, "the .pgpass twin holds the placeholders, the colon escaped");
    ok("pg-scram-prefer", /^alice\|true$/m);
    ok("pg-md5-disable", /^bob\|true$/m);
    ok("pg-scram-require", /^alice\|true$/m);
    ok("pg-scram-verify-full", /^alice\|true$/m);
    ok("pg-md5-verify-full", /^bob\|true$/m);
    ok("pg-ip-notls-prefer", /^carol\|false$/m);
    ok("pg-ip-notls-disable", /^carol\|false$/m);
    // By a name the relay offers the client TLS, then finds the server has
    // none: refused, and libpq's sslmode=prefer retries in plain text, as it
    // would against the server itself; sslmode=require fails, as it would.
    ok("pg-name-notls-prefer", /^carol\|false$/m);
    refused("pg-name-notls-require", /does not offer TLS, and the client asked for it/);
    // pg_dump reads the .pgpass twin unasked (the relay puts the password
    // back: arbiter wireServableDbTwin, found by this suite 2026-10-25).
    ok("pg-dump", /^2$/m);
    refused("pg-cross-unbound", /was not put back/);
    assert.match(c["my-twin"]!, /^password=\$MDU:/m, "the .my.cnf twin holds the placeholders");
    ok("my-native", /^alice@%\|\S+$/m);
    ok("my-sha2-fast", /^bob@%\|\S+$/m);
    ok("my-native-required", /^alice@%\|\S+$/m);
    refused("my-sha2-full", /ssl-ca/);
    refused("my-cross-unbound", /was not put back/);

    // ~/.my.cnf naming the server's CA: dave's first login (the full path)
    // goes through with the client's TLS unverified (ssl-mode=REQUIRED);
    // a client left to verify (the default once ssl-ca is set, or
    // VERIFY_CA) refuses the relay's leaf (db-login-release.md §8.5, open).
    const withCa = out.launches!.find((l) => l.name === "mycnf-ssl-ca")!;
    assert.equal(withCa.code, 0, `the ssl-ca launch failed${diag(withCa)}`);
    assert.equal(caseExit(withCa.cases["my-ca-sha2-full-required"]!), 0, `my-ca-sha2-full-required${diag(withCa)}`);
    assert.match(withCa.cases["my-ca-sha2-full-required"]!, /^dave@%\|\S+$/m);
    for (const name of ["my-ca-sha2-full-default", "my-ca-native-default", "my-ca-native-verify-ca"]) {
      assert.notEqual(caseExit(withCa.cases[name]!), 0, `${name}: a verifying client accepted the relay's leaf (update db-login-release.md §8.5)${diag(withCa)}`);
      assert.match(withCa.cases[name]!, /certificate verify failed/, `${name}${diag(withCa)}`);
    }

    // The variables: the agent sees placeholders, the relay logs each in.
    const envl = out.launches!.find((l) => l.name === "env-vars")!;
    assert.equal(envl.code, 0, `the env-vars launch failed${diag(envl)}`);
    assert.match(envl.cases["env-twin"]!, /^\$MDU:\S+\n\$MDU:\S+\n/, `the variables are placeholders${diag(envl)}`);
    for (const [name, re] of [["pg-env-pgpassword", /^alice\|true$/m], ["my-env-mysql-pwd", /^alice@%\|\S+$/m]] as const) {
      assert.equal(caseExit(envl.cases[name]!), 0, `${name} failed${diag(envl)}`);
      assert.match(envl.cases[name]!, re, `${name}${diag(envl)}`);
    }

    // A host no file names: the agent's own connect is refused by the guard
    // (the session's network rules), before a byte is sent.
    for (const name of ["pg-decoy-direct", "my-decoy-direct"]) refused(name, /Permission denied|\(13\)/);

    // ── the decoys: never given a password ───────────────────────────────
    for (const [k, d] of Object.entries(decoys)) {
      assert.ok(d.logins.every((x) => !x.ok), `a login succeeded at the ${k} decoy: a password reached an unbound host`);
      const got = Buffer.from(d.received, "base64").toString("latin1");
      for (const [name, s] of Object.entries(secrets)) for (const f of secretForms(s)) assert.ok(!got.includes(f), `${name}'s password reached the ${k} decoy`);
    }

    // ── THE ORACLE, every launch ──────────────────────────────────────────
    for (const l of out.launches!) {
      assert.ok(l.model.some((b) => b.includes('"tool_result"')), `${l.name}: the agent sent its tool results to the model`);
      assert.ok(l.model.some((b) => b.includes("$MDU")), `${l.name}: the model got placeholders`);
      const where: Array<[string, string]> = [
        ["a request the model received", l.model.join("\n")],
        ["what the agent's world saw", Object.values(l.cases).join("\n")],
        ["the session's events", l.events],
        ["the launch's output", l.outTail],
      ];
      for (const [name, s] of Object.entries(secrets)) {
        for (const f of secretForms(s)) for (const [w, text] of where) assert.ok(!text.includes(f), `${l.name}: ${name}'s password in ${w}`);
      }
      for (const [rel, text] of Object.entries(launches.find((x) => x.name === l.name)!.files)) {
        assert.equal(l.homeAfter[rel], text, `${l.name}: ~/${rel} unchanged`);
      }
    }
    keep = false;
  } finally {
    killServers(dir);
    if (keep) console.error(`live-db-clients: kept ${dir}`);
    else rmSync(dir, { recursive: true, force: true });
  }
});
