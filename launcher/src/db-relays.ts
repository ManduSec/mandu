/**
 * db-relays — which databases a launch opens a login relay for, and how the
 * agent's world is pointed at them (docs/design/confidentiality/
 * db-login-release.md).
 *
 * The egress proxy opens one loopback relay per database (net-proxy
 * db-relay.ts); the connect guard performs the agent tree's connects to
 * that database on the relay instead (`--redirect`). The databases are the
 * ones the launch's own files and environment name, read here by the
 * launcher (the human's side, before the agent runs):
 *
 *   - each line of the password file (`PGPASSFILE`, else `~/.pgpass`): its
 *     host and port fields only (a `*` port is 5432); a `*` host names no one
 *     database and a socket directory (`/…`) no TCP one, so neither gets a
 *     relay;
 *   - `PGHOST` (a comma list, paired with `PGPORT`'s) when `PGPASSWORD` is
 *     set, since that password is then sent there (the arbiter binds
 *     `PGPASSWORD` to a single-host `PGHOST:PGPORT` from the same
 *     environment, which `applyEnvSecrets` sends it whole: secret-extract.ts
 *     `dbEnvWireHost`, db-login-release.md §3.3.1; `MYSQL_PWD` likewise);
 *   - MySQL: each section of `~/.my.cnf` that holds a password, at the host
 *     and port it (or `[client]`) names (3306 when none; `localhost` is the
 *     client's socket, no TCP), and `MYSQL_HOST` / `MYSQL_TCP_PORT` when
 *     `MYSQL_PWD` is set.
 *
 * Pure but for `dbRelayTargets`' file read and `writeDbRootCert`'s write.
 *
 * Mandu-new (no reference origin).
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { isIP } from "node:net";

import { publishFile } from "./safe-file.js";

/** One database the egress proxy relays logins to (net-proxy db-relay.ts
 *  `DbRelayTarget`). */
export interface DbRelayTarget {
  protocol: "postgres" | "mysql";
  host: string;
  port: number;
}

/** A relay the proxy opened: its target and its loopback port. */
export interface DbRelayBound extends DbRelayTarget {
  listen: number;
}

/** The variables the net-proxy reads (server-main.ts). */
export const NET_PROXY_DB_RELAYS_ENV = "MANDU_NET_PROXY_DB_RELAYS";
export const NET_PROXY_DB_RELAY_PORT_FILE_ENV = "MANDU_DB_RELAY_PORT_FILE";

/** At most this many relays per launch (a password file listing more is
 *  cut, and the launch says so). */
export const MAX_DB_RELAYS = 32;

export const PG_DEFAULT_PORT = 5432;
export const MYSQL_DEFAULT_PORT = 3306;

/** A pgpass line's fields, split on unescaped colons, `\:` and `\\`
 *  unescaped. */
function pgpassFields(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (c === "\\" && i + 1 < line.length) { cur += line[i + 1]; i++; continue; }
    if (c === ":") { out.push(cur); cur = ""; continue; }
    cur += c;
  }
  out.push(cur);
  return out;
}

/** A host a relay can be keyed by: a DNS name or an IP literal, no `*`, no
 *  socket path. */
function relayHost(h: string): string | null {
  const host = h.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "" || host === "*" || host.startsWith("/") || host.startsWith("@")) return null;
  if (isIP(host) !== 0) return host;
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(host) ? host : null;
}

function relayPort(p: string | undefined): number | null {
  const s = (p ?? "").trim();
  if (s === "" || s === "*") return PG_DEFAULT_PORT;
  if (!/^\d{1,5}$/.test(s)) return null;
  const n = Number(s);
  return n > 0 && n < 65536 ? n : null;
}

/** The databases of a pgpass file's text (host and port fields only). Pure. */
export function pgpassTargets(text: string): DbRelayTarget[] {
  const out: DbRelayTarget[] = [];
  for (const raw of text.split(/\r?\n/)) {
    if (raw.trim() === "" || raw.startsWith("#")) continue;
    const f = pgpassFields(raw);
    if (f.length < 5) continue;
    const host = relayHost(f[0]!);
    const port = relayPort(f[1]);
    if (host === null || port === null) continue;
    out.push({ protocol: "postgres", host, port });
  }
  return out;
}

/** The databases `PGHOST` / `PGPORT` name when `PGPASSWORD` is set. Pure. */
export function pgEnvTargets(env: Record<string, string | undefined>): DbRelayTarget[] {
  if ((env["PGPASSWORD"] ?? "") === "") return [];
  const hosts = (env["PGHOST"] ?? "").split(",");
  const ports = (env["PGPORT"] ?? "").split(",");
  const out: DbRelayTarget[] = [];
  hosts.forEach((h, i) => {
    const host = relayHost(h);
    const port = relayPort(ports.length === 1 ? ports[0] : ports[i]);
    if (host !== null && port !== null) out.push({ protocol: "postgres", host, port });
  });
  return out;
}

/** The databases of a `~/.my.cnf`'s text: each section holding a password,
 *  at the host and port it or `[client]` names. Pure. */
export function mycnfTargets(text: string): DbRelayTarget[] {
  const vals = new Map<string, Map<string, string>>();
  let section = "";
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const sec = /^\[([^\]]+)\]$/.exec(line);
    if (sec) { section = sec[1]!.trim().toLowerCase(); continue; }
    const kv = /^([A-Za-z_-]+)\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    const key = kv[1]!.toLowerCase().replace(/_/g, "-");
    if (!vals.has(section)) vals.set(section, new Map());
    vals.get(section)!.set(key, kv[2]!.trim().replace(/^(['"])(.*)\1$/, "$2"));
  }
  const out: DbRelayTarget[] = [];
  for (const kv of vals.values()) {
    if (!kv.has("password")) continue;
    const h = kv.get("host") ?? vals.get("client")?.get("host");
    if (!h || h.toLowerCase() === "localhost") continue;
    const host = relayHost(h);
    const port = relayPort(kv.get("port") ?? vals.get("client")?.get("port") ?? String(MYSQL_DEFAULT_PORT));
    if (host !== null && port !== null) out.push({ protocol: "mysql", host, port });
  }
  return out;
}

/** The database `MYSQL_HOST` / `MYSQL_TCP_PORT` name when `MYSQL_PWD` is
 *  set. Pure. */
export function mysqlEnvTargets(env: Record<string, string | undefined>): DbRelayTarget[] {
  if ((env["MYSQL_PWD"] ?? "") === "") return [];
  const h = (env["MYSQL_HOST"] ?? "").trim();
  if (h === "" || h.toLowerCase() === "localhost") return [];
  const host = relayHost(h);
  const port = relayPort((env["MYSQL_TCP_PORT"] ?? "").trim() || String(MYSQL_DEFAULT_PORT));
  return host !== null && port !== null ? [{ protocol: "mysql", host, port }] : [];
}

/**
 * The launch's database targets: the password file's (`PGPASSFILE`, else
 * `<home>/.pgpass`) and the environment's, de-duplicated, at most
 * `MAX_DB_RELAYS` (`cut` says how many more there were). An unreadable
 * file names none.
 */
export function dbRelayTargets(
  env: Record<string, string | undefined>,
  home: string,
  read: (p: string) => string = (p) => readFileSync(p, "utf8"),
): { targets: DbRelayTarget[]; cut: number } {
  const file = (env["PGPASSFILE"] ?? "").trim() || join(home, ".pgpass");
  let text = "";
  try { text = read(file); } catch { text = ""; }
  let mycnf = "";
  try { mycnf = read(join(home, ".my.cnf")); } catch { mycnf = ""; }
  const all = [...pgpassTargets(text), ...pgEnvTargets(env), ...mycnfTargets(mycnf), ...mysqlEnvTargets(env)];
  const seen = new Set<string>();
  const targets: DbRelayTarget[] = [];
  for (const t of all) {
    const k = `${t.host}:${t.port}`;
    if (seen.has(k)) continue;
    seen.add(k);
    targets.push(t);
  }
  return { targets: targets.slice(0, MAX_DB_RELAYS), cut: Math.max(0, targets.length - MAX_DB_RELAYS) };
}

/** Parse the relay port file the net-proxy publishes. Entries that do not
 *  name a target the launch asked for, or a loopback port, are dropped:
 *  the guard would redirect to them. Pure. */
export function parseDbRelayPorts(text: string, asked: readonly DbRelayTarget[]): DbRelayBound[] {
  let list: unknown;
  try { list = JSON.parse(text); } catch { return []; }
  if (!Array.isArray(list)) return [];
  const out: DbRelayBound[] = [];
  for (const e of list) {
    const o = e as Partial<DbRelayBound>;
    const t = asked.find((a) => a.host === o.host && a.port === o.port && a.protocol === o.protocol);
    if (!t || typeof o.listen !== "number" || !Number.isInteger(o.listen) || o.listen <= 0 || o.listen > 65535) continue;
    out.push({ ...t, listen: o.listen });
  }
  return out;
}

/** A guard host token: an IPv6 literal bracketed. */
function guardHost(host: string): string {
  return isIP(host) === 6 ? `[${host}]` : host;
}

/** The connect guard's `--redirect` specs: each database's connects
 *  performed on its relay. Pure. */
export function dbGuardRedirects(relays: readonly DbRelayBound[]): string[] {
  return relays.map((r) => `tcp:${guardHost(r.host)}:${r.port}=127.0.0.1:${r.listen}`);
}

/** The relays' loopback ports (the guard's allow rules and its
 *  session-proxy exception). Pure. */
export function dbRelayPorts(relays: readonly DbRelayBound[] | undefined): number[] {
  return [...new Set((relays ?? []).map((r) => r.listen))].sort((a, b) => a - b);
}

/**
 * The file the agent's libpq trusts (`PGSSLROOTCERT`) when the relays
 * answer its TLS with the session CA's leaf: the session CA, after the
 * user's own Postgres root certificate (`PGSSLROOTCERT`, else
 * `<home>/.postgresql/root.crt`) when there is one, so a database the agent
 * reaches directly (a law `destinations:` allowance) still verifies. With
 * this set, libpq's `sslmode=require` verifies the relay's leaf (a root
 * certificate exists), and `verify-full` checks the database's name on it.
 * Never throws: undefined when nothing could be written.
 */
export function writeDbRootCert(
  caDir: string,
  sessionCaPem: string,
  env: Record<string, string | undefined>,
  home: string,
  io: { read: (p: string) => string; write: (p: string, data: string) => void } = {
    read: (p) => readFileSync(p, "utf8"),
    write: (p, data) => publishFile(p, data, { mode: 0o644 }),
  },
): string | undefined {
  let session: string;
  try { session = io.read(sessionCaPem); } catch { return undefined; }
  const named = (env["PGSSLROOTCERT"] ?? "").trim();
  const userPath = named !== "" && named !== "system" ? named : join(home, ".postgresql", "root.crt");
  let user = "";
  try {
    const pem = io.read(userPath);
    if (pem.includes("-----BEGIN CERTIFICATE-----")) user = `${pem.replace(/\s*$/, "")}\n`;
  } catch { /* none */ }
  const out = join(caDir, "mandu-pg-root.pem");
  try { io.write(out, `${user}${session.replace(/\s*$/, "")}\n`); } catch { return undefined; }
  return out;
}
