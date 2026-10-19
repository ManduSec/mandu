/**
 * data-locations — the product page's "Where your data lives" projection
 * (GET /api/data-locations; on-disk-layout.md §9 decision 2, dashboard.md
 * §4.25): every place Mandu keeps a file, what it holds in plain words,
 * whether it exists, its mode, and whether that mode is owner-only. The same
 * data as `mandu paths` (launcher/src/paths-command.ts), which a person can
 * run in a terminal to see it too.
 *
 * Mandu-new (no reference origin). MIRRORED, not imported: the dashboard is a
 * standalone package. The path table is the dashboard's generated copy
 * (src/generated/mandu-paths.ts); the plain descriptions and the row rule
 * (table order, a path listed once) mirror paths-command.ts, and a unit test
 * (test/unit/data-locations.test.ts) reads that file and fails when the two
 * name lists drift.
 *
 * Only locations: each path is `stat`ed (metadata only, following a symlink
 * to its target's mode as `mandu paths` does) and never opened or listed, so
 * no file content reaches the response. A dangling symlink is there but
 * broken (`exists: true`, `brokenLink: true`, no mode), the rule `mandu paths`
 * follows too (on-disk-layout.md §5 "A broken link"). Pure apart from the
 * injected `stat` and `lexists`.
 */

import { lstatSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { resolveRuntimeBase } from "./runtime-base.js";
import {
  MANDU_BASES,
  MANDU_PATHS,
  manduPath,
  type ManduPathEnv,
  type ManduPathName,
} from "./generated/mandu-paths.js";

type Env = Readonly<Record<string, string | undefined>>;

/** What each location holds, in plain words: launcher/src/paths-command.ts
 *  PATH_DESCRIPTIONS, verbatim (the parity test compares the names). */
export const LOCATION_DESCRIPTIONS: Readonly<Record<ManduPathName, string>> = {
  "mandu-home": "Mandu's folder: your settings at the top, Mandu's own data in the folders below",
  "config-root": "your settings",
  "config-toml": "your default settings (written by mandu init and mandu mode)",
  "policy": "your rules: which files, hosts and models count as secret",
  "packs": "rule packs you installed",
  "pack-keys": "the keys of the rule-pack publishers you trust",
  "prompt-filters": "your pattern packs for checking your own prompt",
  "secrets-json": "API keys for Mandu's developer tools",
  "dashboard-env": "settings for a dashboard that runs as a service, including its login password",
  "state-root": "Mandu's lasting data; deleting it loses your approvals and history",
  "symbol-db": "the placeholders the AI saw, the real values behind them, and your approvals",
  "symbol-db-test": "the same, for Mandu's own tests",
  "view-state": "Mandu's copies of your projects",
  "workspaces": "Mandu's copies of the projects you ran it in",
  "object-walks": "notes from checking your git history for protected files",
  "paired-approvals": "one-time approvals for evaluation runs (developers)",
  "browser-profile": "the Chrome profile of the browser Mandu starts for your agent (mandu --browser): your logins on the sites it uses",
  "launch-logs": "what each launch said: its notices, warnings and helper messages (mandu log shows the latest); the last 20 launches",
  "events": "session history, kept 90 days; it includes the real values behind placeholders",
  "events-test": "session history of Mandu's own tests",
  "runs-root": "test and evaluation results (developers)",
  "test-runs": "the test-run history the dashboard shows (developers)",
  "test-run-results": "the results of each test run started from the dashboard (developers)",
  "live-drill-runs": "results of live test drills (developers)",
  "ci-runs": "results of CI runs (developers)",
  "matrix-results": "results of runs across operating systems (developers)",
  "eval-runs": "evaluation results (developers)",
  "replay-drill-runs": "results of replayed test drills (developers)",
  "drill-baselines": "saved runs of the AI tools without Mandu, for comparing test drills (developers)",
  "dev-root": "files for Mandu's developers",
  "docker-e2e-home": "logins for Mandu's container tests (developers)",
  "cache-root": "files Mandu can rebuild; safe to delete",
  "object-twins": "copies of your git data with the protected files taken out",
  "exec-box-cache": "a copy of a Mandu helper, used when the runtime folder is under /tmp",
  "ci-cache": "virtual machine images for Mandu's CI (developers)",
  "ci-host-out": "CI output waiting to be collected (developers)",
  "dashboard-cache": "the dashboard's saved session-list summaries, so it starts fast; safe to delete",
  "update-check": "the answer of the last check for a newer Mandu release; safe to delete",
  "runtime-dir": "running services and per-session files; cleared when the machine restarts",
  "install-prefix": "the installed Mandu program",
  "bin-dir": "where the mandu command is installed",
};

/** The places only Mandu's own developers use (their descriptions say
 *  "(developers)" or "Mandu's own tests", and `dev-root`). On a user's machine
 *  none exist, so the product page lists one only when it is there
 *  (dashboard.md §4.25q); `mandu paths` still lists them all. A unit test
 *  fails when a new developer path is not named here. */
export const DEVELOPER_LOCATIONS: ReadonlySet<ManduPathName> = new Set<ManduPathName>([
  "symbol-db-test",
  "paired-approvals",
  "events-test",
  "runs-root",
  "test-runs",
  "test-run-results",
  "live-drill-runs",
  "ci-runs",
  "matrix-results",
  "eval-runs",
  "replay-drill-runs",
  "drill-baselines",
  "dev-root",
  "docker-e2e-home",
  "ci-cache",
  "ci-host-out",
]);

export interface DataLocation {
  /** The path table's entry name (`mandu paths --json` uses the same). */
  name: ManduPathName;
  /** The path, the user's home spelled `~`. */
  path: string;
  /** In Mandu's folder, or outside it (the runtime dir, the install). */
  where: "home" | "outside";
  /** What it holds, in plain words. */
  holds: string;
  /** Only Mandu's own developers use it (DEVELOPER_LOCATIONS). */
  developer: boolean;
  /** Something is at the path, a dangling symlink included. */
  exists: boolean;
  /** A symlink whose target is not there: `exists` true, `mode` null. */
  brokenLink: boolean;
  /** The permission bits as octal (`"0700"`), a symlink's target's; null
   *  when it is not there or is a broken link. */
  mode: string | null;
  /** For a location the agent may not read (every store in Mandu's folder):
   *  true when no one but the owner can open it, false when group or others
   *  can. null when that does not apply: the table lets the agent read it,
   *  or it is not there. */
  ownerOnly: boolean | null;
}

export interface DataLocations {
  /** Mandu's folder, `~`-abbreviated (`~/.mandu` by default). */
  home: string;
  locations: DataLocation[];
}

/** The one filesystem read: metadata only (a symlink is followed to its
 *  target's mode, never into its contents); null when absent or dangling. */
export type StatFn = (p: string) => { mode: number } | null;

export const realStat: StatFn = (p) => {
  try {
    return statSync(p);
  } catch {
    return null;
  }
};

/** Whether anything is at `p`, not following a final symlink (a dangling one
 *  counts): `mandu paths`' `exists`. */
export type LexistsFn = (p: string) => boolean;

export const realLexists: LexistsFn = (p) => {
  try {
    lstatSync(p);
    return true;
  } catch {
    return false;
  }
};

/** The home paths resolve under: HOME, else the OS's (paths-command homeOf). */
export function homeOf(env: Env): string {
  return env["HOME"] || homedir();
}

/** `p` with the user's home shortened to `~` (paths-command tilde). */
export function tilde(p: string, userHome: string): string {
  if (userHome.length <= 1) return p;
  if (p === userHome) return "~";
  return p.startsWith(userHome + "/") ? "~" + p.slice(userHome.length) : p;
}

function octal(mode: number): string {
  return "0" + mode.toString(8).padStart(3, "0");
}

/** The base an entry finally resolves under. */
function rootBase(name: ManduPathName): string {
  let b: string = MANDU_PATHS[name].base;
  while (!Object.prototype.hasOwnProperty.call(MANDU_BASES, b)) b = MANDU_PATHS[b as ManduPathName].base;
  return b;
}

/** Build the projection. Rows come in the table's order; a path already
 *  listed under another name (`config-root`, `view-state`) is not repeated —
 *  the same rows as `mandu paths`. */
export function buildDataLocations(env: Env, home: string, stat: StatFn = realStat, lexists: LexistsFn = realLexists): DataLocations {
  const e = env as ManduPathEnv;
  const seen = new Set<string>();
  const locations: DataLocation[] = [];
  for (const name of Object.keys(MANDU_PATHS) as ManduPathName[]) {
    const entry = MANDU_PATHS[name];
    // The runtime dir is the table's under the runtime-base rule: on macOS a
    // TMPDIR too long for a socket makes it /tmp/mandu-<uid>
    // (runtime-instances.md §3b), the same row `mandu paths` prints.
    const path = name === "runtime-dir" ? resolveRuntimeBase(env).base : manduPath(name, e, home);
    if (seen.has(path)) continue;
    seen.add(path);
    const st = stat(path);
    const mode = st ? st.mode & 0o7777 : null;
    const brokenLink = st === null && lexists(path);
    locations.push({
      name,
      path: tilde(path, home),
      where: rootBase(name) === "mandu" ? "home" : "outside",
      holds: LOCATION_DESCRIPTIONS[name],
      developer: DEVELOPER_LOCATIONS.has(name),
      exists: st !== null || brokenLink,
      brokenLink,
      mode: mode === null ? null : octal(mode),
      ownerOnly: entry.agentReadable || mode === null ? null : (mode & 0o077) === 0,
    });
  }
  return { home: tilde(manduPath("mandu-home", e, home), home), locations };
}
