/**
 * live-db — the shared half of the live database client suite
 * (docs/design/testing/live-clients.md §2): what it needs from the host,
 * the servers' and the users' configuration, and the case list.
 *
 * The suite runs the REAL `psql` and `mysql` clients under a launched Mandu
 * session against REAL PostgreSQL and MySQL servers on "the other machine"
 * of tests/lib/netns.ts (10.77.0.2: no address of the session's machine, so
 * the egress proxy's relay dials it as it would a database on the LAN; the
 * proxy refuses this machine's own addresses, blocked-destinations.ts).
 * Three processes share this module:
 *
 *   - the test (sandbox/launcher/live-db-clients.test.ts) writes the config
 *     (passwords made here, the certificates), starts the topology, and
 *     reads the scenario's JSON;
 *   - the peer (fixtures/live-db-peer.fixture.ts, in the peer namespace)
 *     starts the servers as the test's own user (a nested user namespace
 *     maps it back: Postgres refuses to run as root), creates the users,
 *     and the decoys;
 *   - the scenario (fixtures/live-db-scenario.fixture.ts, this side) writes
 *     the launch HOME's files, launches Mandu around a stand-in `claude`
 *     driven by a scripted model, and reports each case's output.
 *
 * PROVENANCE: NEW Mandu test code.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";

import { TWO_HOST } from "./netns.js";
import type { LiveCase } from "./live-clients.js";

/** The names the scenario's hosts file gives the other machine. */
export const LIVE_DB_HOSTS = {
  pg: "pg.mandu-live.test",
  /** pg2 (no TLS) by a name. */
  pg2: "pg2.mandu-live.test",
  my: "mysql.mandu-live.test",
} as const;

export interface LiveDbConfig {
  /** The suite's own directory (data dirs, sockets, certificates, logs). */
  dir: string;
  /** The test's own uid and gid: the servers run as them (nested userns). */
  uid: number;
  gid: number;
  bins: { pgBin: string; psql: string; mysqld: string; mysql: string; mysqlMajorMinor: string };
  /** The other machine's address on the network, and its address outside it. */
  addr: string;
  outside: string;
  pg: {
    /** pg1: TLS on (the certificate for LIVE_DB_HOSTS.pg), alice (SCRAM) and bob (md5). */
    port: number;
    /** pg2: no TLS, carol (SCRAM), named by its IP literal in ~/.pgpass. */
    port2: number;
    alice: string;
    bob: string;
    carol: string;
  };
  my: {
    port: number;
    /** A fake MySQL on the other machine's address, a relay target the
     *  ~/.my.cnf names for eve: where another section's placeholder must
     *  not be put back. */
    evePort: number;
    /** alice: mysql_native_password ([client]). */
    alice: string;
    /** bob: caching_sha2_password, the server's cache warmed by the peer
     *  (the fast path). */
    bob: string;
    /** dave: caching_sha2_password, never logged in (the full path). */
    dave: string;
    eve: string;
  };
  certs: { ca: string; pgCert: string; pgKey: string; myCert: string; myKey: string };
  /** The peer writes this when every server listens and every user exists. */
  ready: string;
  /** The decoys' records (JSON, rewritten as they change). */
  decoyLog: string;
  /** The peer's own log (each server's start, the setup's statements). */
  peerLog: string;
}

/** A password made of letters and digits after a fixed prefix (no quote,
 *  backslash or shell character), with `extra` inside it. */
export function livePassword(prefix: string, extra = ""): string {
  const abc = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const tail = [...randomBytes(18)].map((b) => abc[b % abc.length]).join("");
  return `${prefix}${tail.slice(0, 9)}${extra}${tail.slice(9)}`;
}

/** The newest /usr/lib/postgresql/<major>/bin holding postgres, initdb and
 *  psql (MANDU_LIVE_PG_BIN wins), or null. */
export function pgBinDir(): string | null {
  const own = process.env["MANDU_LIVE_PG_BIN"];
  const has = (d: string): boolean => ["postgres", "initdb", "psql"].every((b) => existsSync(join(d, b)));
  if (own) return has(own) ? own : null;
  const base = "/usr/lib/postgresql";
  if (!existsSync(base)) return null;
  const majors = readdirSync(base).filter((v) => /^\d+$/.test(v)).sort((a, b) => Number(b) - Number(a));
  for (const v of majors) if (has(join(base, v, "bin"))) return join(base, v, "bin");
  return null;
}

const which = (cmd: string): string | null => {
  const r = spawnSync("sh", ["-c", `command -v ${cmd}`], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : null;
};

/** The binaries the suite runs, or the reason it SKIPs. */
export function liveDbBins(): LiveDbConfig["bins"] | string {
  const pgBin = pgBinDir();
  if (!pgBin) return "no PostgreSQL server (postgres, initdb and psql under /usr/lib/postgresql/<major>/bin, or MANDU_LIVE_PG_BIN)";
  const psql = which("psql") ?? join(pgBin, "psql");
  const mysqld = which("mysqld") ?? (existsSync("/usr/sbin/mysqld") ? "/usr/sbin/mysqld" : null);
  const mysql = which("mysql");
  if (!mysqld || !mysql) return "no MySQL server and client (mysqld, mysql)";
  const v = spawnSync(mysqld, ["--version"], { encoding: "utf8" });
  const m = /Ver (\d+)\.(\d+)\./.exec(v.stdout ?? "");
  if (!m) return `mysqld --version printed no version (${(v.stdout || v.stderr || "").trim().slice(0, 120)})`;
  if (!/MariaDB/i.test(v.stdout) && Number(m[1]) < 8) return `mysqld is ${m[1]}.${m[2]}; the suite needs MySQL 8 (caching_sha2_password)`;
  if (/MariaDB/i.test(v.stdout)) return "mysqld is MariaDB; the suite needs MySQL 8 (caching_sha2_password)";
  const u = spawnSync("unshare", ["--user", `--map-user=${process.getuid?.() ?? 0}`, "--", "true"], { encoding: "utf8" });
  if (u.status !== 0) return `unshare --map-user does not work here (${(u.stderr || "").trim().slice(0, 120)})`;
  return { pgBin, psql, mysqld, mysql, mysqlMajorMinor: `${m[1]}.${m[2]}` };
}

/** The other machine's addresses (tests/lib/netns.ts). */
export const LIVE_DB_ADDR = { addr: TWO_HOST.inside, outside: TWO_HOST.outside } as const;

/** The placeholder of the n-th `.pgpass` line, as libpq reads it (the
 *  twin writes its colons escaped). */
export const pgpassPlaceholder = (line: number): string =>
  `"$(sed -n ${line}p ~/.pgpass | cut -d: -f5- | sed 's/\\\\:/:/g')"`;

/** The placeholder of the n-th `password=` line of `~/.my.cnf`. */
export const mycnfPlaceholder = (n: number): string => `"$(sed -n 's/^password=//p' ~/.my.cnf | sed -n ${n}p)"`;

const PG = LIVE_DB_HOSTS.pg;
const SELECT_WHO = `-At -c "select current_user || '|' || coalesce((select ssl::text from pg_stat_ssl where pid = pg_backend_pid()), 'none')"`;

/** The PostgreSQL cases. `.pgpass` lines: 1 alice at pg:5432, 2 bob at
 *  pg:5432, 3 carol at 10.77.0.2:5433 (the IP literal). */
export function pgCases(addr: string, outside: string, port2: number): LiveCase[] {
  return [
    { name: "pg-twin", cmd: "cat ~/.pgpass" },
    { name: "pg-scram-prefer", cmd: `psql -h ${PG} -U alice -d app ${SELECT_WHO}` },
    { name: "pg-md5-disable", cmd: `PGSSLMODE=disable psql -h ${PG} -U bob -d app ${SELECT_WHO}` },
    { name: "pg-scram-require", cmd: `psql "host=${PG} user=alice dbname=app sslmode=require" ${SELECT_WHO}` },
    { name: "pg-scram-verify-full", cmd: `psql "host=${PG} user=alice dbname=app sslmode=verify-full" ${SELECT_WHO}` },
    { name: "pg-md5-verify-full", cmd: `psql "host=${PG} user=bob dbname=app sslmode=verify-full" ${SELECT_WHO}` },
    // pg2 has no TLS: psql's default (sslmode=prefer) asks for it and falls
    // back to plain, as it would without Mandu.
    { name: "pg-ip-notls-prefer", cmd: `psql -h ${addr} -p ${port2} -U carol -d postgres ${SELECT_WHO}` },
    { name: "pg-ip-notls-disable", cmd: `psql "host=${addr} port=${port2} user=carol dbname=postgres sslmode=disable" ${SELECT_WHO}` },
    // The same server by a name (`.pgpass` line 4): the relay can offer the
    // client TLS for a name (a session-CA leaf), which it cannot for an IP.
    { name: "pg-name-notls-prefer", cmd: `psql -h ${LIVE_DB_HOSTS.pg2} -p ${port2} -U carol -d postgres ${SELECT_WHO}` },
    { name: "pg-name-notls-require", cmd: `psql "host=${LIVE_DB_HOSTS.pg2} port=${port2} user=carol dbname=postgres sslmode=require" ${SELECT_WHO}` },
    // pg_dump: libpq too, a known consumer of .pgpass that is not a printer.
    { name: "pg-dump", cmd: `pg_dump -h ${PG} -U alice -d app --schema-only | grep -c 'PostgreSQL database dump'` },
    // alice's placeholder at carol's database (a relay target the file
    // binds to carol's password only): refused, nothing put back.
    { name: "pg-cross-unbound", cmd: `PGPASSWORD=${pgpassPlaceholder(1)} psql "host=${addr} port=${port2} user=carol dbname=postgres sslmode=disable" -c "select 1"` },
    // alice's placeholder to a host no line names (no relay: psql connects
    // itself): the decoy asks for the password in cleartext and records it.
    { name: "pg-decoy-direct", cmd: `PGPASSWORD=${pgpassPlaceholder(1)} psql "host=${outside} user=alice dbname=app sslmode=disable connect_timeout=5" -c "select 1"` },
  ];
}

/** The variable logins (db-login-release.md §3.3.1), for a launch whose
 *  environment holds PGPASSWORD + PGHOST and MYSQL_PWD + MYSQL_HOST (alice's
 *  real passwords) and whose HOME holds no password file: each placeholder
 *  is bound to the host variable beside it. */
export function envCases(): LiveCase[] {
  return [
    { name: "env-twin", cmd: "printenv PGPASSWORD MYSQL_PWD PGHOST MYSQL_HOST" },
    { name: "pg-env-pgpassword", cmd: `psql -U alice -d app ${SELECT_WHO}` },
    { name: "my-env-mysql-pwd", cmd: `mysql -u alice ${MY_WHO}` },
  ];
}

const MY = LIVE_DB_HOSTS.my;
const MY_WHO = `-N -B -e "select concat(current_user(), '|', coalesce((select variable_value from performance_schema.session_status where variable_name = 'Ssl_cipher'), ''))"`;

/** The MySQL cases. `~/.my.cnf` sections, in order: [client] alice,
 *  [client_bob] bob, [client_dave] dave, [client_eve] eve (port evePort). */
export function myCases(outside: string): LiveCase[] {
  return [
    { name: "my-twin", cmd: "cat ~/.my.cnf" },
    { name: "my-native", cmd: `mysql ${MY_WHO}` },
    { name: "my-sha2-fast", cmd: `mysql --defaults-group-suffix=_bob ${MY_WHO}` },
    { name: "my-sha2-full", cmd: `mysql --defaults-group-suffix=_dave ${MY_WHO}` },
    { name: "my-native-required", cmd: `mysql --ssl-mode=REQUIRED ${MY_WHO}` },
    // alice's placeholder at eve's relay target: refused, nothing put back.
    { name: "my-cross-unbound", cmd: `mysql --defaults-group-suffix=_eve -u alice -p${mycnfPlaceholder(1)} -e "select 1"` },
    // alice's placeholder to a host no section names: the decoy records the
    // native answer (a hash of what the client holds).
    { name: "my-decoy-direct", cmd: `mysql --no-defaults -h ${outside} -u alice -p${mycnfPlaceholder(1)} --connect-timeout=5 -e "select 1"` },
  ];
}

/** The MySQL cases of a `~/.my.cnf` whose [client] names the server's CA
 *  (`ssl-ca`): the relay verifies the server, so caching_sha2's full path
 *  can be served; the client, given a CA, verifies the relay's leaf too. */
export function myCasesWithCa(): LiveCase[] {
  return [
    { name: "my-ca-sha2-full-required", cmd: `mysql --defaults-group-suffix=_dave --ssl-mode=REQUIRED ${MY_WHO}` },
    { name: "my-ca-sha2-full-default", cmd: `mysql --defaults-group-suffix=_dave ${MY_WHO}` },
    { name: "my-ca-native-default", cmd: `mysql ${MY_WHO}` },
    { name: "my-ca-native-verify-ca", cmd: `mysql --ssl-mode=VERIFY_CA ${MY_WHO}` },
  ];
}
