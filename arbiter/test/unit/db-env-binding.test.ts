/**
 * db-env-binding — `PGPASSWORD` bound to `PGHOST` and `MYSQL_PWD` to
 * `MYSQL_HOST` automatically, when the host variable is in the same launch
 * environment (db-login-release.md §3.3, maintainer decision 2026-10-25), the
 * way pip's index variable is bound to its URL's host:
 *
 *   - `dbEnvWireHost`: exactly one TCP database, else nothing (a socket
 *     directory, a libpq host list, an empty or unparseable value, MySQL's
 *     `localhost`); loopback Postgres is bound like any host (§3.7);
 *   - `envSecretSpan`: the wire mark on the whole plain value only, never
 *     without the launch environment, never past an exemption;
 *   - `registerEnvSecret`: the binding added beside the law's, dropped when
 *     the same value is registered again with no host;
 *   - `wireReleaseScheme`: a database password variable's row answers its
 *     login's scheme, bound or not, so the gate never puts it back in an
 *     HTTP(S) request (`wireSchemeRefusal`).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { dbEnvWireHost, envSecretSpan } from "../../policy/secret-extract.js";
import { registerEnvSecret, wireReleaseScheme } from "../../secret-registry/registry.js";
import { getSymbolEntry, loadSymbolMap } from "../../symbol-table/symbol-table.js";
import { wireSchemeRefusal } from "../../policy/policy-interface.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const PG_PW = "pgEnvPW_DBENV_7q";
const MY_PW = "myEnvPW_DBENV_3z";

test("dbEnvWireHost: PGHOST at PGPORT (5432 by default) is the one database PGPASSWORD goes to", () => {
  const pg = (env: Record<string, string>) => dbEnvWireHost("PGPASSWORD", env);
  assert.equal(pg({ PGHOST: "db.internal" }), "db.internal:5432");
  assert.equal(pg({ PGHOST: "db.internal", PGPORT: "" }), "db.internal:5432", "an empty PGPORT is libpq's default");
  assert.equal(pg({ PGHOST: "DB.Internal", PGPORT: "6543" }), "db.internal:6543", "lower case, as the relay keys it");
  assert.equal(pg({ PGHOST: "10.0.0.7", PGPORT: "5433" }), "10.0.0.7:5433");
  assert.equal(pg({ PGHOST: "2001:DB8:0::1" }), "[2001:db8::1]:5432", "IPv6 bracketed and canonical");
  // A database on this machine: bound like any host (libpq connects there
  // over TCP; the relay checks who listens, db-login-release.md §3.7).
  assert.equal(pg({ PGHOST: "localhost" }), "localhost:5432");
  assert.equal(pg({ PGHOST: "127.0.0.1" }), "127.0.0.1:5432");
  assert.equal(pg({ PGHOST: "::1" }), "[::1]:5432");
});

test("dbEnvWireHost: no host, a socket directory, a host list, an empty or unparseable value bind nothing (fail-closed)", () => {
  const pg = (env: Record<string, string>) => dbEnvWireHost("PGPASSWORD", env);
  for (const env of [
    {},                                              // libpq's socket
    { PGHOST: "" },
    { PGPORT: "5432" },                              // a port with no host
    { PGHOST: "/var/run/postgresql" },               // a socket directory
    { PGHOST: "/tmp", PGPORT: "5432" },
    { PGHOST: "@abstract" },                         // an abstract socket
    { PGHOST: "a.corp,b.corp" },                     // libpq's multi-host list
    { PGHOST: "a.corp,b.corp", PGPORT: "5432,5433" },
    { PGHOST: "db.internal", PGPORT: "5432,5433" },  // several ports
    { PGHOST: "db.internal,", PGPORT: "5432" },
    { PGHOST: "*" },
    { PGHOST: " db.internal" },                      // whitespace: not what libpq dials
    { PGHOST: "db.internal " },
    { PGHOST: "db internal" },
    { PGHOST: "db\\.internal" },
    { PGHOST: "db.internal:5432" },                  // a port inside the host
    { PGHOST: "[::1]" },                             // libpq takes no brackets
    { PGHOST: "fe80::1%eth0" },                      // a zone id
    { PGHOST: "user@db.internal" },
    { PGHOST: "db_.internal" },
    { PGHOST: "db.internal", PGPORT: "*" },
    { PGHOST: "db.internal", PGPORT: "0" },
    { PGHOST: "db.internal", PGPORT: "65536" },
    { PGHOST: "db.internal", PGPORT: "123456" },
    { PGHOST: "db.internal", PGPORT: " 5432" },
    { PGHOST: "db.internal", PGPORT: "postgres" },
    { PGHOST: "db.internal", PGPORT: "-1" },
  ] as Array<Record<string, string>>) {
    assert.equal(pg(env), null, JSON.stringify(env));
  }
});

test("dbEnvWireHost: MYSQL_HOST at MYSQL_TCP_PORT (3306 by default); localhost is the client's socket, so nothing", () => {
  const my = (env: Record<string, string>) => dbEnvWireHost("MYSQL_PWD", env);
  assert.equal(my({ MYSQL_HOST: "mysql.internal" }), "mysql.internal:3306");
  assert.equal(my({ MYSQL_HOST: "mysql.internal", MYSQL_TCP_PORT: "3310" }), "mysql.internal:3310");
  assert.equal(my({ MYSQL_HOST: "127.0.0.1" }), "127.0.0.1:3306", "a loopback address is TCP");
  assert.equal(my({ MYSQL_HOST: "::1" }), "[::1]:3306");
  for (const env of [{}, { MYSQL_HOST: "" }, { MYSQL_HOST: "localhost" }, { MYSQL_HOST: "LocalHost" }, { MYSQL_HOST: "/run/mysqld/mysqld.sock" }, { MYSQL_HOST: "a,b" }, { MYSQL_HOST: "m.corp", MYSQL_TCP_PORT: "x" }, { MYSQL_HOST: "m.corp", MYSQL_TCP_PORT: "0" }] as Array<Record<string, string>>) {
    assert.equal(my(env), null, JSON.stringify(env));
  }
  // Each password takes its own client's host variable, and no other name binds.
  assert.equal(dbEnvWireHost("PGPASSWORD", { MYSQL_HOST: "mysql.internal" }), null);
  assert.equal(dbEnvWireHost("MYSQL_PWD", { PGHOST: "db.internal" }), null);
  for (const name of ["DB_PASSWORD", "PGPASSFILE", "MYSQL_PASSWORD", "PGPASSWORD_X"]) {
    assert.equal(dbEnvWireHost(name, { PGHOST: "db.internal", MYSQL_HOST: "mysql.internal" }), null, name);
  }
});

test("envSecretSpan: PGPASSWORD / MYSQL_PWD are marked for their database's login only with the launch environment; an exemption still wins", () => {
  const env = { PGHOST: "db.internal", PGPORT: "6432", MYSQL_HOST: "mysql.internal" };
  assert.deepEqual(envSecretSpan("PGPASSWORD", PG_PW, {}, env), {
    key: "PGPASSWORD", start: 0, end: PG_PW.length, value: PG_PW,
    wire: { host: "db.internal:6432", scheme: "postgres", httpsOnly: false },
  });
  assert.deepEqual(envSecretSpan("MYSQL_PWD", MY_PW, {}, env)?.wire, { host: "mysql.internal:3306", scheme: "mysql", httpsOnly: false });
  // Without the environment (every caller before this change), no host.
  assert.equal(envSecretSpan("PGPASSWORD", PG_PW)?.wire, undefined);
  // No host in it: masked as before, nothing bound (each login asks).
  assert.deepEqual(envSecretSpan("PGPASSWORD", PG_PW, {}, { PGHOST: "/var/run/postgresql" }), { key: "PGPASSWORD", start: 0, end: PG_PW.length, value: PG_PW });
  // The user's exemption keeps the variable raw: no span, no binding.
  assert.equal(envSecretSpan("PGPASSWORD", PG_PW, { exempt: ["PGPASSWORD"] }, env), null);
  assert.equal(envSecretSpan("MYSQL_PWD", MY_PW, { exempt: ["MYSQL_*"] }, env), null);
  // Named by the law (an env.sources variable): still bound.
  assert.equal(envSecretSpan("PGPASSWORD", PG_PW, { secrets: ["PGPASSWORD"] }, env)?.wire?.host, "db.internal:6432");
  // A URL's password is not the login password the client sends: unbound.
  const url = envSecretSpan("PGPASSWORD", `postgres://u:${PG_PW}@db.internal/app`, {}, env);
  assert.equal(url?.value, PG_PW);
  assert.equal(url?.wire, undefined);
  // Another password variable is never bound by PGHOST.
  assert.equal(envSecretSpan("DB_PASSWORD", PG_PW, {}, env)?.wire, undefined);
});

test("registerEnvSecret: PGPASSWORD's row is bound to PGHOST:PGPORT beside the law's bindings; registered again without PGHOST the host is gone", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dbenv-"));
  const dbPath = join(dir, "symbols.db");
  try {
    const map = loadSymbolMap(dbPath);
    const r = registerEnvSecret(map, { name: "PGPASSWORD", value: PG_PW, launchEnv: { PGHOST: "db.internal" } }, dbPath);
    assert.ok(r.symbol, r.reason);
    assert.equal(r.twin, r.symbol, "the agent's environment holds the placeholder only");
    assert.equal(r.wireHost, "db.internal:5432");
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["db.internal:5432"]);
    assert.equal(getSymbolEntry(map, r.symbol!)?.value, PG_PW);
    // The law's own binding rides beside the automatic one.
    const both = registerEnvSecret(map, { name: "PGPASSWORD", value: PG_PW, bindings: ["replica.internal:5432"], launchEnv: { PGHOST: "db.internal" } }, dbPath);
    assert.equal(both.symbol, r.symbol);
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["replica.internal:5432", "db.internal:5432"]);
    // A later launch without PGHOST: the earlier host is not kept.
    const bare = registerEnvSecret(map, { name: "PGPASSWORD", value: PG_PW, launchEnv: {} }, dbPath);
    assert.equal(bare.symbol, r.symbol);
    assert.equal(bare.wireHost, undefined);
    assert.equal(getSymbolEntry(map, r.symbol!)?.bindings ?? null, null);
    // MySQL the same way; localhost binds nothing.
    const my = registerEnvSecret(map, { name: "MYSQL_PWD", value: MY_PW, launchEnv: { MYSQL_HOST: "mysql.internal", MYSQL_TCP_PORT: "3307" } }, dbPath);
    assert.deepEqual(getSymbolEntry(map, my.symbol!)?.bindings, ["mysql.internal:3307"]);
    const sock = registerEnvSecret(map, { name: "MYSQL_PWD", value: MY_PW, launchEnv: { MYSQL_HOST: "localhost" } }, dbPath);
    assert.equal(sock.wireHost, undefined);
    assert.equal(getSymbolEntry(map, my.symbol!)?.bindings ?? null, null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("wireReleaseScheme: a database password variable's row answers its login's scheme, bound or not; the scheme rule refuses it in any HTTP(S) request", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dbenv-"));
  const dbPath = join(dir, "symbols.db");
  try {
    const map = loadSymbolMap(dbPath);
    const pg = registerEnvSecret(map, { name: "PGPASSWORD", value: PG_PW, launchEnv: { PGHOST: "db.internal" } }, dbPath).symbol!;
    const pgUnbound = registerEnvSecret(map, { name: "PGPASSWORD", value: `${PG_PW}_2`, launchEnv: {} }, dbPath).symbol!;
    const my = registerEnvSecret(map, { name: "MYSQL_PWD", value: MY_PW, launchEnv: { MYSQL_HOST: "mysql.internal" } }, dbPath).symbol!;
    const other = registerEnvSecret(map, { name: "DB_PASSWORD", value: "otherPW_DBENV_1", launchEnv: { PGHOST: "db.internal" } }, dbPath).symbol!;
    assert.equal(wireReleaseScheme(map, pg), "postgres");
    assert.equal(wireReleaseScheme(map, pgUnbound), "postgres", "unbound too: a libpq password is only ever a login's");
    assert.equal(wireReleaseScheme(map, my), "mysql");
    assert.equal(wireReleaseScheme(map, other), null, "another variable is untouched");
    const net = (scheme?: string) => ({ boundary: "network" as const, destination: "db.internal:5432", ...(scheme ? { scheme } : {}) }) as Parameters<typeof wireSchemeRefusal>[0];
    assert.equal(wireSchemeRefusal(net("postgres"), "postgres"), null, "the relay's own login");
    for (const s of ["http", "https", undefined, "mysql"]) {
      const r = wireSchemeRefusal(net(s), "postgres");
      assert.equal(r?.allow, false, String(s));
      assert.equal(r?.requiresApproval, false, "a hard refusal, no approval");
      assert.equal(r?.ruleRef?.id, "egress:secret-db-login-only");
    }
    assert.equal(wireSchemeRefusal(net("postgres"), "mysql")?.allow, false, "MYSQL_PWD in a Postgres login");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
