/**
 * live-db-peer.fixture — "the other machine" of the live database client
 * suite (docs/design/testing/live-clients.md §2), run by tests/lib/netns.ts
 * in the peer's network namespace (10.77.0.2 and 203.0.113.9):
 *
 *   - pg1: a real PostgreSQL at 10.77.0.2:5432, TLS on with a certificate
 *     for pg.mandu-live.test from the suite's own CA; alice logs in by
 *     SCRAM-SHA-256, bob by md5 (his password stored as md5);
 *   - pg2: a second cluster at 10.77.0.2:5433, no TLS; carol by SCRAM;
 *   - a real MySQL at 10.77.0.2:3306, TLS with a certificate for
 *     mysql.mandu-live.test; alice (mysql_native_password), bob
 *     (caching_sha2_password, logged in once here so the server's cache
 *     holds him: the fast path) and dave (caching_sha2_password, never
 *     logged in: the full path);
 *   - decoys that record every byte (tests the relay must never feed):
 *     a fake MySQL for eve at 10.77.0.2:<evePort>, and at 203.0.113.9 a
 *     fake PostgreSQL that asks for the password in cleartext (:5432) and a
 *     fake MySQL (:3306), each knowing alice's real password, so a login
 *     that succeeds there IS a leak.
 *
 * The servers run as the test's own user: a nested user namespace maps it
 * back from the namespace's root (Postgres refuses to run as root, and the
 * data directories belong to that user). The users are made over each
 * server's Unix socket. Writes LiveDbConfig.ready when all of it is up;
 * stops the servers on SIGTERM / SIGINT (and the test kills what a pid file
 * still names).
 *
 * env: LIVE_DB_CONFIG (the LiveDbConfig JSON).
 * PROVENANCE: NEW Mandu test code.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { LiveDbConfig } from "../lib/live-db.js";
import { startFakePostgres, type FakePostgres } from "../../interceptors/net-proxy/test/fake-postgres.js";
import { startFakeMysql, type FakeMysql } from "../../interceptors/net-proxy/test/fake-mysql.js";

const cfg = JSON.parse(readFileSync(process.env["LIVE_DB_CONFIG"]!, "utf8")) as LiveDbConfig;
const log = (s: string): void => { appendFileSync(cfg.peerLog, `${new Date().toISOString()} ${s}\n`); };
/** argv run as the test's own user (uid and gid), from this namespace's root. */
const asUser = (argv: string[]): string[] => ["unshare", "--user", `--map-user=${cfg.uid}`, `--map-group=${cfg.gid}`, "--", ...argv];
const children: ChildProcess[] = [];

function runSync(what: string, argv: string[], input?: string): string {
  const [cmd, ...args] = asUser(argv);
  const r = spawnSync(cmd!, args, { encoding: "utf8", input, timeout: 180_000 });
  log(`${what}: exit ${r.status} ${(r.stderr ?? "").trim().slice(0, 2000)}`);
  if (r.status !== 0) throw new Error(`${what} failed (exit ${r.status}): ${(r.stderr || r.stdout || "").trim().slice(0, 2000)}`);
  return r.stdout;
}

function startServer(what: string, argv: string[]): void {
  const [cmd, ...args] = asUser(argv);
  const out = join(cfg.dir, `${what}.out`);
  const child = spawn(cmd!, args, { stdio: ["ignore", "pipe", "pipe"] });
  child.stdout!.on("data", (d: Buffer) => appendFileSync(out, d));
  child.stderr!.on("data", (d: Buffer) => appendFileSync(out, d));
  child.on("exit", (code, sig) => log(`${what} exited (${code ?? sig})`));
  children.push(child);
}

async function waitFor(what: string, ok: () => boolean, ms = 90_000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (ok()) return;
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`${what} did not come up in ${ms / 1000}s`);
}

const sock = (name: string): string => join(cfg.dir, "s", name);

// ── PostgreSQL ─────────────────────────────────────────────────────────────
async function postgres(name: string, port: number, tls: boolean, hba: string[], listen = cfg.addr): Promise<void> {
  const data = join(cfg.dir, name);
  runSync(`initdb ${name}`, [join(cfg.bins.pgBin, "initdb"), "-D", data, "-U", "postgres", "--auth-local=trust", "--auth-host=reject", "-E", "UTF8", "--no-instructions"]);
  writeFileSync(join(data, "pg_hba.conf"), ["local all postgres trust", ...hba, ""].join("\n"));
  const conf = [
    `listen_addresses = '${listen}'`, `port = ${port}`, `unix_socket_directories = '${join(cfg.dir, "s")}'`,
    "log_connections = on", "log_destination = 'stderr'", "fsync = off", "shared_buffers = 16MB",
    ...(tls ? ["ssl = on", `ssl_cert_file = '${cfg.certs.pgCert}'`, `ssl_key_file = '${cfg.certs.pgKey}'`] : ["ssl = off"]),
  ];
  appendFileSync(join(data, "postgresql.conf"), conf.join("\n") + "\n");
  startServer(name, [join(cfg.bins.pgBin, "postgres"), "-D", data]);
  await waitFor(name, () => existsSync(sock(`.s.PGSQL.${port}`)));
  await waitFor(`${name} accepting`, () => spawnSync(asUser([cfg.bins.psql])[0]!, asUser([cfg.bins.psql, "-h", join(cfg.dir, "s"), "-p", String(port), "-U", "postgres", "-d", "postgres", "-Atc", "select 1"]).slice(1), { encoding: "utf8" }).stdout?.trim() === "1");
}

const psqlAdmin = (port: number, sql: string): string =>
  runSync(`psql :${port}`, [cfg.bins.psql, "-v", "ON_ERROR_STOP=1", "-h", join(cfg.dir, "s"), "-p", String(port), "-U", "postgres", "-d", "postgres", "-At"], sql);

// ── MySQL ──────────────────────────────────────────────────────────────────
async function mysql(): Promise<void> {
  const data = join(cfg.dir, "mysql-data");
  const files = join(cfg.dir, "mysql-files");
  mkdirSync(files, { recursive: true });
  const common = ["--no-defaults", `--datadir=${data}`, `--secure-file-priv=${files}`, `--tmpdir=${cfg.dir}`];
  runSync("mysqld --initialize-insecure", [cfg.bins.mysqld, ...common, "--initialize-insecure", `--log-error=${join(cfg.dir, "mysql-init.err")}`]);
  const [major, minor] = cfg.bins.mysqlMajorMinor.split(".").map(Number) as [number, number];
  // 8.4 loads mysql_native_password only when asked (8.0 has it on).
  const native = major > 8 || (major === 8 && minor >= 4) ? ["--mysql-native-password=ON"] : [];
  startServer("mysqld", [
    cfg.bins.mysqld, ...common, `--port=${cfg.my.port}`, `--bind-address=${cfg.addr}`, `--socket=${sock("mysql.sock")}`,
    `--pid-file=${join(cfg.dir, "mysqld.pid")}`, `--log-error=${join(cfg.dir, "mysqld.err")}`, "--mysqlx=OFF",
    `--ssl-ca=${cfg.certs.ca}`, `--ssl-cert=${cfg.certs.myCert}`, `--ssl-key=${cfg.certs.myKey}`,
    "--innodb-buffer-pool-size=32M", "--skip-log-bin", ...native,
  ]);
  await waitFor("mysqld", () => existsSync(sock("mysql.sock")), 120_000);
  await waitFor("mysqld accepting", () => spawnSync(asUser([cfg.bins.mysql])[0]!, asUser([cfg.bins.mysql, "--no-defaults", "-uroot", `--socket=${sock("mysql.sock")}`, "-N", "-e", "select 1"]).slice(1), { encoding: "utf8" }).stdout?.trim() === "1", 120_000);
}

const mysqlAdmin = (sql: string): string =>
  runSync("mysql root", [cfg.bins.mysql, "--no-defaults", "-uroot", `--socket=${sock("mysql.sock")}`, "-N"], sql);

// ── the decoys ─────────────────────────────────────────────────────────────
const decoys: Record<string, FakePostgres | FakeMysql> = {};
function writeDecoys(): void {
  const out: Record<string, { logins: unknown; connections: number; received: string }> = {};
  for (const [k, d] of Object.entries(decoys)) out[k] = { logins: d.logins, connections: d.connections(), received: d.received().toString("base64") };
  writeFileSync(cfg.decoyLog, JSON.stringify(out));
}

function stop(): void {
  for (const c of children) { try { c.kill("SIGTERM"); } catch { /* gone */ } }
  try { writeDecoys(); } catch { /* best effort */ }
}
process.on("SIGTERM", () => { stop(); process.exit(0); });
process.on("SIGINT", () => { stop(); process.exit(0); });

async function main(): Promise<void> {
  mkdirSync(join(cfg.dir, "s"), { recursive: true });
  const { alice, bob, carol } = cfg.pg;
  await postgres("pg1", cfg.pg.port, true, [
    "host all alice 0.0.0.0/0 scram-sha-256",
    "host all bob 0.0.0.0/0 md5",
  ]);
  psqlAdmin(cfg.pg.port, [
    "SET password_encryption = 'scram-sha-256';",
    `CREATE ROLE alice LOGIN PASSWORD '${alice}';`,
    "SET password_encryption = 'md5';",
    `CREATE ROLE bob LOGIN PASSWORD '${bob}';`,
    "CREATE DATABASE app OWNER alice;",
    "GRANT CONNECT ON DATABASE app TO bob;",
    "SELECT rolname || ':' || left(rolpassword, 6) FROM pg_authid WHERE rolname IN ('alice', 'bob') ORDER BY 1;",
  ].join("\n"));
  // pg2 also at the outside address: the name LIVE_DB_HOSTS.pg2 resolves there
  await postgres("pg2", cfg.pg.port2, false, ["host all carol 0.0.0.0/0 scram-sha-256"], `${cfg.addr},${cfg.outside}`);
  psqlAdmin(cfg.pg.port2, `SET password_encryption = 'scram-sha-256';\nCREATE ROLE carol LOGIN PASSWORD '${carol}';\n`);

  await mysql();
  const { alice: ma, bob: mb, dave: md } = cfg.my;
  mysqlAdmin([
    `CREATE USER 'alice'@'%' IDENTIFIED WITH mysql_native_password BY '${ma}';`,
    `CREATE USER 'bob'@'%' IDENTIFIED WITH caching_sha2_password BY '${mb}';`,
    `CREATE USER 'dave'@'%' IDENTIFIED WITH caching_sha2_password BY '${md}';`,
    "GRANT SELECT ON performance_schema.* TO 'alice'@'%', 'bob'@'%', 'dave'@'%';",
    "FLUSH PRIVILEGES;",
  ].join("\n"));
  // bob's first login, over TLS, fills the server's cache: his logins
  // through the relay then take the fast path (db-login-release.md §8.2).
  runSync("mysql bob warm-up", [cfg.bins.mysql, "--no-defaults", "-h", cfg.addr, `-P${cfg.my.port}`, "-ubob", `-p${mb}`, "--ssl-mode=REQUIRED", "-N", "-e", "select 1"]);

  decoys["eve"] = await startFakeMysql({ plugin: "native", user: "eve", password: cfg.my.eve, host: cfg.addr, port: cfg.my.evePort });
  decoys["pgOutside"] = await startFakePostgres({ method: "password", user: "alice", password: cfg.pg.alice, host: cfg.outside, port: 5432 });
  decoys["myOutside"] = await startFakeMysql({ plugin: "native", user: "alice", password: cfg.my.alice, host: cfg.outside, port: 3306 });
  setInterval(writeDecoys, 200).unref();
  writeDecoys();
  log("ready");
  writeFileSync(cfg.ready, "up\n");
  // Stay until the topology is torn down.
  setInterval(() => {}, 1 << 30);
}

main().catch((e) => {
  log(`FAILED: ${(e as Error).stack ?? e}`);
  stop();
  process.exit(1);
});
