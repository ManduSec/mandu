/**
 * dashboard-auth — the credentials a live suite needs to query the RUNNING
 * dashboard daemon (the `dashboard-daemon-fresh` stale-daemon alarm,
 * e2e-catalog.md §2b) now that the daemon gates every route behind HTTP Basic
 * auth (dashboard.md §6.z, DASHBOARD_BASIC_AUTH). Without this the alarm
 * WARNed `HTTP 401` on every run since 2026-09-15 and never compared anything.
 *
 * Resolution order (first hit wins), mirroring how the daemon itself is fed:
 *   1. `DASHBOARD_BASIC_AUTH=user:password` in the suite's own env — the
 *      dashboard's test-runner spawns suites with its process env, so a run
 *      started from the ▶ Run drawer inherits the daemon's value;
 *   2. the systemd unit's env file `~/.mandu/dashboard.env` (mode
 *      600, KEY=VALUE lines, `#` comments, optional quotes) — a hand run from
 *      a shell that never sourced it. The path table's `dashboard-env` entry
 *      (on-disk-layout.md §5), resolved under HOME alone: every suite runs
 *      with MANDU_HOME pinned to /dev/null/mandu-test-home
 *      (run-suites.mjs FIXED_ENV), and the unit reads `%h/.mandu`;
 *   3. nothing → no header (an unauthenticated daemon answers anyway; an
 *      authenticated one 401s and the alarm WARNs as before).
 *
 * The password is read and used ONLY as a request header to loopback; it is
 * never logged, echoed into a check reason, or written anywhere.
 */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, posix } from "node:path";

import { manduPath } from "../../dashboard/src/generated/mandu-paths.js";

/** The env file, relative to HOME: the path table's `dashboard-env` for a
 *  home without MANDU_HOME (`.mandu/dashboard.env`). */
export const DASHBOARD_ENV_FILE = posix.relative("/h", manduPath("dashboard-env", {}, "/h"));

/** Parse a systemd-style EnvironmentFile: `KEY=VALUE` per line, `#` comments,
 *  blank lines, an optional `export ` prefix and one layer of matching quotes.
 *  The first `=` splits (a password may contain `=`). */
export function parseEnvFile(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const body = line.startsWith("export ") ? line.slice("export ".length).trim() : line;
    const eq = body.indexOf("=");
    if (eq <= 0) continue;
    const key = body.slice(0, eq).trim();
    let value = body.slice(eq + 1).trim();
    if (value.length >= 2 && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))) {
      value = value.slice(1, -1);
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) out[key] = value;
  }
  return out;
}

/** The `user:password` pair, or undefined. `env` and `home` are injectable for tests. */
export function resolveDashboardBasicAuth(
  env: NodeJS.ProcessEnv = process.env,
  home: string = homedir(),
  readFile: (p: string) => string = (p) => readFileSync(p, "utf8"),
): string | undefined {
  const fromEnv = env["DASHBOARD_BASIC_AUTH"];
  if (typeof fromEnv === "string" && fromEnv.includes(":") && !fromEnv.startsWith(":")) return fromEnv;
  try {
    const parsed = parseEnvFile(readFile(join(home, DASHBOARD_ENV_FILE)));
    const v = parsed["DASHBOARD_BASIC_AUTH"];
    if (typeof v === "string" && v.includes(":") && !v.startsWith(":")) return v;
  } catch {
    /* no env file — an unauthenticated daemon, or none */
  }
  return undefined;
}

/** The request headers for the daemon: `{ Authorization: "Basic …" }` (RFC
 *  7617) when credentials resolve, else `{}`. */
export function dashboardAuthHeaders(
  env: NodeJS.ProcessEnv = process.env,
  home: string = homedir(),
  readFile?: (p: string) => string,
): Record<string, string> {
  const pair = resolveDashboardBasicAuth(env, home, readFile);
  return pair ? { Authorization: `Basic ${Buffer.from(pair, "utf8").toString("base64")}` } : {};
}

/** A human-readable hint for the WARN reason when the daemon answers 401 — the
 *  run had no credentials (or wrong ones); never echoes a value. */
export function unauthorizedHint(hadCredentials: boolean): string {
  return hadCredentials
    ? "HTTP 401 with credentials present — DASHBOARD_BASIC_AUTH does not match the daemon's"
    : `HTTP 401 — the daemon requires Basic auth; set DASHBOARD_BASIC_AUTH=user:password or keep it in ~/${DASHBOARD_ENV_FILE}`;
}
