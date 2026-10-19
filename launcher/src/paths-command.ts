/**
 * paths-command — `mandu paths` (docs/design/architecture/on-disk-layout.md §5): every
 * place Mandu keeps a file, with what it holds, whether it exists, and its
 * mode next to the one Mandu gives it; then the places outside Mandu's
 * folder. For users who want to know what Mandu stores, and for bug
 * reports. `--json` gives the same report.
 *
 * Pure apart from `stat` / `exists`, which are injected (tests pass fakes or
 * a temporary HOME). `mandu doctor` reuses the report (doctor-home.ts).
 *
 * A dangling symlink (on-disk-layout.md §5, "A broken link"): something IS at
 * the path, so it counts as there (`exists`), with no mode and `brokenLink`
 * set; the text says "broken link". The dashboard's "Where your data lives"
 * (dashboard/src/data-locations.ts) follows the same rule.
 *
 * Mandu-new (no reference origin).
 */
import { statSync, lstatSync } from "node:fs";
import { homedir } from "node:os";
import { resolveRuntimeBase } from "./runtime-base.js";
import {
  MANDU_BASES,
  MANDU_PATHS,
  manduPath,
  type ManduPathEnv,
  type ManduPathName,
} from "./generated/mandu-paths.js";

type Env = Record<string, string | undefined>;

/** What each location holds, in plain words (the table's own notes are for
 *  developers and are not in the generated copy). */
export const PATH_DESCRIPTIONS: Readonly<Record<ManduPathName, string>> = {
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

/** The filesystem reads the report needs. */
export interface PathsDeps {
  /** The permission bits of `p` (following a symlink), or null when absent. */
  stat: (p: string) => { mode: number } | null;
  /** Whether anything is at `p`, not following a final symlink (a dangling
   *  one counts). */
  exists: (p: string) => boolean;
}

export const realPathsDeps: PathsDeps = {
  stat: (p) => {
    try {
      return { mode: statSync(p).mode & 0o7777 };
    } catch {
      return null;
    }
  },
  exists: (p) => {
    try {
      lstatSync(p);
      return true;
    } catch {
      return false;
    }
  },
};

export interface PathRow {
  name: ManduPathName;
  path: string;
  /** In Mandu's folder, or outside it (the runtime dir, the install). */
  where: "home" | "outside";
  holds: string;
  exists: boolean;
  /** The actual permission bits (a symlink's target's), or null when it does
   *  not exist or is a broken link. */
  mode: number | null;
  /** A symlink whose target is not there: `exists` is true, `mode` null. */
  brokenLink: boolean;
  /** The bits Mandu gives it, or null when it is not Mandu's to set. */
  expectedMode: number | null;
  /** Group or other users can reach something the agent may not read. */
  loose: boolean;
}

export interface PathsReport {
  home: string;
  /** The user's home directory; the text shortens paths under it to `~`. */
  userHome: string;
  rows: PathRow[];
}

/** The base an entry finally resolves under. */
function rootBase(name: ManduPathName): string {
  let b: string = MANDU_PATHS[name].base;
  while (!Object.prototype.hasOwnProperty.call(MANDU_BASES, b)) b = MANDU_PATHS[b as ManduPathName].base;
  return b;
}

/** Group or other access. */
export function isLoose(mode: number): boolean {
  return (mode & 0o077) !== 0;
}

/** The home directory paths resolve under: HOME, else the OS's. */
export function homeOf(env: Env): string {
  return env["HOME"] || homedir();
}

/** Build the report. Entries come in the table's order (the §3 layout); an
 *  entry that resolves to a path already listed (`config-root` and
 *  `view-state` are the home and `state/` under another name) is not repeated. */
export function gatherPaths(env: Env, home: string, deps: PathsDeps): PathsReport {
  const e = env as ManduPathEnv;
  const rows: PathRow[] = [];
  const seen = new Set<string>();
  for (const name of Object.keys(MANDU_PATHS) as ManduPathName[]) {
    const entry = MANDU_PATHS[name];
    // The runtime dir is the table's under the runtime-base rule: on macOS a
    // TMPDIR too long for a socket makes it /tmp/mandu-<uid> (§3b).
    const path = name === "runtime-dir" ? resolveRuntimeBase(env).base : manduPath(name, e, home);
    if (seen.has(path)) continue;
    seen.add(path);
    const st = deps.stat(path);
    const brokenLink = st === null && deps.exists(path);
    const exists = st !== null || brokenLink;
    const mode = st?.mode ?? null;
    rows.push({
      name,
      path,
      where: rootBase(name) === "mandu" ? "home" : "outside",
      holds: PATH_DESCRIPTIONS[name],
      exists,
      mode,
      brokenLink,
      expectedMode: entry.mode,
      loose: !entry.agentReadable && mode !== null && isLoose(mode),
    });
  }
  return { home: manduPath("mandu-home", e, home), userHome: home, rows };
}

/** `0700`, or `-` for none. */
export function octal(mode: number | null): string {
  return mode === null ? "-" : "0" + mode.toString(8).padStart(3, "0");
}

/** Quote a path for a shell command when it needs it. */
export function shq(s: string): string {
  return /^[A-Za-z0-9_./@%+=:,-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

/** `p` with the user's home shortened to `~`, for reading. */
export function tilde(p: string, userHome: string): string {
  if (userHome.length <= 1) return p;
  if (p === userHome) return "~";
  return p.startsWith(userHome + "/") ? "~" + p.slice(userHome.length) : p;
}

/** `p` as a shell word, the home as `~` (left unquoted so the shell expands it). */
export function shPath(p: string, userHome: string): string {
  const t = tilde(p, userHome);
  if (t === "~") return t;
  return t.startsWith("~/") ? "~/" + shq(t.slice(2)) : shq(p);
}

/** The `chmod` commands that make the loose paths owner-only. */
export function chmodCommands(loose: readonly { path: string; dir: boolean }[], userHome = ""): string[] {
  const dirs = loose.filter((l) => l.dir).map((l) => shPath(l.path, userHome));
  const files = loose.filter((l) => !l.dir).map((l) => shPath(l.path, userHome));
  return [
    ...(dirs.length > 0 ? [`chmod 700 ${dirs.join(" ")}`] : []),
    ...(files.length > 0 ? [`chmod 600 ${files.join(" ")}`] : []),
  ];
}

function modeWords(r: PathRow): string {
  if (!r.exists) return "not there yet";
  if (r.brokenLink) return "broken link";
  if (r.mode === null) return "present";
  const shown = octal(r.mode);
  const note = r.expectedMode !== null && r.mode !== r.expectedMode ? ` (Mandu sets ${octal(r.expectedMode)})` : "";
  return `${shown}${note}${r.loose ? " (!)" : ""}`;
}

function rowLines(rows: readonly PathRow[], userHome: string): string[] {
  const shown = rows.map((r) => tilde(r.path, userHome));
  const pw = Math.min(60, Math.max(...shown.map((p) => p.length)));
  const mw = Math.max(...rows.map((r) => modeWords(r).length));
  return rows.map((r, i) => `  ${shown[i]!.padEnd(pw)}  ${modeWords(r).padEnd(mw)}  ${r.holds}`);
}

/** The report in plain words. Pure. */
export function renderPaths(r: PathsReport): string {
  const L: string[] = [];
  const inHome = r.rows.filter((x) => x.where === "home");
  const outside = r.rows.filter((x) => x.where === "outside");
  L.push("Where Mandu keeps its files");
  L.push("");
  const t = (p: string): string => tilde(p, r.userHome);
  L.push(`Mandu's folder: ${t(r.home)}`);
  L.push("  Everything Mandu stores for you is in this one folder. Only you should be able to open it.");
  L.push("");
  L.push(...rowLines(inHome, r.userHome));
  const loose = inHome.filter((x) => x.loose);
  if (loose.length > 0) {
    L.push("");
    L.push("  (!) Other users on this machine can open these. To make them yours only:");
    for (const c of chmodCommands(loose.map((x) => ({ path: x.path, dir: MANDU_PATHS[x.name].kind === "dir" })), r.userHome)) L.push(`      ${c}`);
  }
  L.push("");
  L.push("Outside Mandu's folder");
  L.push(...rowLines(outside, r.userHome));
  if (r.rows.some((x) => x.brokenLink)) {
    L.push("");
    L.push("  A broken link points at something that is not there: Mandu cannot use that place until");
    L.push("  the link's target is back (a disk not mounted?) or the link is removed.");
  }

  L.push("");
  return L.join("\n");
}

/** The report as JSON (modes as octal strings). */
export function pathsJson(r: PathsReport): string {
  return JSON.stringify({
    home: r.home,
    paths: r.rows.map((x) => ({
      name: x.name,
      path: x.path,
      where: x.where,
      holds: x.holds,
      exists: x.exists,
      mode: x.mode === null ? null : octal(x.mode),
      brokenLink: x.brokenLink,
      expectedMode: x.expectedMode === null ? null : octal(x.expectedMode),
      loose: x.loose,
    })),
  }, null, 2) + "\n";
}

/** `mandu paths [--json]`. Always exits 0 (a report). */
export function runPaths(
  rest: string[],
  env: Env,
  deps: PathsDeps = realPathsDeps,
  out: (s: string) => void = (s) => { process.stdout.write(s); },
): number {
  const unknown = rest.find((a) => a !== "--json");
  if (unknown !== undefined) {
    process.stderr.write(`mandu paths: unknown option '${unknown}' (see mandu paths --help)\n`);
    return 2;
  }
  const report = gatherPaths(env, homeOf(env), deps);
  out(rest.includes("--json") ? pathsJson(report) : renderPaths(report));
  return 0;
}
