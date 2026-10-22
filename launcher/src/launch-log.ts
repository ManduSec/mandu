/**
 * launch-log — the per-launch log file and `mandu log` (packaging.md §5
 * "Launch display policy", 2026-10-18).
 *
 * A launch in the default display shows one banner line (and a short line
 * per protection warning) and writes everything else here: every launch
 * line in full (the per-layer lines, the notices, the warnings), the
 * non-fatal messages of Mandu's own helpers while the agent runs (the
 * network guard, the reply filter: `MANDU_LAUNCH_LOG` names this file to
 * them), the error that stopped a launch, and the lines said after the agent
 * exits. Never the agent's own output, and nothing the terminal would not
 * have shown under `--verbose`: the same lines (the dashboard's one-time
 * sign-in link stays on the terminal only, policy-surface.md §2.6).
 *
 * Where: `launch-logs/` in Mandu's state folder (`mandu paths`), one file per
 * launch, `<UTC yyyymmddThhmmssmmmZ>-<session id>.log` (a name already taken,
 * as by two in-process launches of one session id, steps the time by a
 * millisecond), the folder 0700 and
 * each file 0600, opened through `safe-log.ts` (no link on the way). Kept:
 * the newest LAUNCH_LOG_KEEP files; a launch that opens a new one removes
 * the older ones. The agent can neither read nor write it (the whole Mandu
 * home is outside its world, write-protect.ts).
 *
 * Mandu-new (no reference origin).
 */
import { closeSync, lstatSync, readdirSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { manduPath } from "./generated/mandu-paths.js";
import { openSafeLog } from "./safe-log.js";
import { SUBCOMMAND_USAGE } from "./subcommand-help.js";
import { formatTimingsTable, timingsFromLog, type LaunchTimings } from "./launch-timings.js";

type Env = Record<string, string | undefined>;

/** How many launch logs are kept. */
export const LAUNCH_LOG_KEEP = 20;
/** How many launches `mandu log --timings` shows side by side. */
export const TIMINGS_SHOWN = 5;
/** The env var that names the launch's log to Mandu's helpers. */
export const LAUNCH_LOG_ENV = "MANDU_LAUNCH_LOG";

const NAME_RE = /^(\d{8}T\d{9}Z)-([A-Za-z0-9._-]+)\.log$/;

function homeOf(env: Env): string {
  return env["HOME"] || homedir();
}

/** The folder the launch logs live in. */
export function launchLogDir(env: Env, home = homeOf(env)): string {
  return manduPath("launch-logs", env, home);
}

/** A launch log's file name: its UTC start to the millisecond, then the session id. Pure. */
export function launchLogName(at: Date, sessionId: string): string {
  const stamp = at.toISOString().slice(0, 23).replace(/[-:.]/g, "") + "Z";
  const id = sessionId.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 96) || "launch";
  return `${stamp}-${id}.log`;
}

export interface LaunchLogEntry {
  name: string;
  path: string;
  startedAt: Date;
  sessionId: string;
}

/** The entry a file name stands for, or null when it is not a launch log. Pure. */
export function parseLaunchLogName(dir: string, name: string): LaunchLogEntry | null {
  const m = NAME_RE.exec(name);
  if (m === null) return null;
  const s = m[1]!;
  const startedAt = new Date(`${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(9, 11)}:${s.slice(11, 13)}:${s.slice(13, 15)}.${s.slice(15, 18)}Z`);
  if (Number.isNaN(startedAt.getTime())) return null;
  return { name, path: join(dir, name), startedAt, sessionId: m[2]! };
}

/** The launch logs among `names`, newest first. Pure. */
export function sortLaunchLogs(dir: string, names: readonly string[]): LaunchLogEntry[] {
  return names
    .map((n) => parseLaunchLogName(dir, n))
    .filter((e): e is LaunchLogEntry => e !== null)
    .sort((a, b) => (a.name < b.name ? 1 : a.name > b.name ? -1 : 0));
}

/** The launch logs to remove so the newest `keep` remain. Pure. */
export function prunableLaunchLogs(names: readonly string[], keep = LAUNCH_LOG_KEEP): string[] {
  return sortLaunchLogs("", names).slice(Math.max(0, keep)).map((e) => e.name);
}

/** The launch logs on disk, newest first ([] when there is no folder). */
export function listLaunchLogs(env: Env, home = homeOf(env)): LaunchLogEntry[] {
  const dir = launchLogDir(env, home);
  try {
    return sortLaunchLogs(dir, readdirSync(dir));
  } catch {
    return [];
  }
}

/** Whether anything is at `p` (a link counts). */
function taken(p: string): boolean {
  try {
    lstatSync(p);
    return true;
  } catch {
    return false;
  }
}

/** One launch's open log. */
export interface LaunchLog {
  readonly path: string;
  /** Append one line (a multi-line note keeps its lines). Best-effort. */
  write(line: string): void;
  close(): void;
}

/**
 * Open this launch's log (created 0600, its folder 0700, nothing followed
 * through a link) and remove the oldest beyond `keep`. null when it cannot
 * be opened: the launch then says where the lines went instead
 * (`--verbose`). Never throws.
 */
export function openLaunchLog(opts: {
  env: Env;
  home?: string;
  sessionId: string;
  now?: Date;
  keep?: number;
  /** The first line: what launched, where, when. */
  header?: string;
}): LaunchLog | null {
  const home = opts.home ?? homeOf(opts.env);
  const dir = launchLogDir(opts.env, home);
  const now = (opts.now ?? new Date()).getTime();
  let path = join(dir, launchLogName(new Date(now), opts.sessionId));
  for (let i = 1; i < 50 && taken(path); i++) path = join(dir, launchLogName(new Date(now + i), opts.sessionId));
  let fd: number;
  try {
    fd = openSafeLog(path, { mode: 0o600, root: manduPath("mandu-home", opts.env, home) });
  } catch {
    return null;
  }
  try {
    for (const n of prunableLaunchLogs(readdirSync(dir), opts.keep ?? LAUNCH_LOG_KEEP)) {
      if (join(dir, n) !== path) { try { unlinkSync(join(dir, n)); } catch { /* gone already */ } }
    }
  } catch { /* retention is best-effort */ }
  let open = true;
  const log: LaunchLog = {
    path,
    write(line) {
      if (!open) return;
      try { writeSync(fd, line.endsWith("\n") ? line : line + "\n"); } catch { /* best-effort */ }
    },
    close() {
      if (!open) return;
      open = false;
      try { closeSync(fd); } catch { /* already closed */ }
    },
  };
  if (opts.header !== undefined) log.write(opts.header);
  return log;
}

/**
 * Text from a log, safe to print on a terminal: every control character but
 * a newline and a tab shown as `?` (a helper's message can carry a host or
 * a path the agent chose; an escape sequence in it must not reach the
 * terminal as one). Pure.
 */
export function printable(text: string): string {
  return text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "?");
}

/** The local-time spelling `--list` uses. Pure. */
function localStamp(d: Date): string {
  const p = (n: number): string => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** The verb's usage (subcommand-help.ts, shown by `mandu log --help` too). */
const LOG_USAGE = SUBCOMMAND_USAGE["log"]!;

export interface LogOut {
  out: (s: string) => void;
  err: (s: string) => void;
}

const realOut: LogOut = {
  out: (s) => { process.stdout.write(s); },
  err: (s) => { process.stderr.write(s); },
};

/** `mandu log`. Exit 0 on success, 1 when there is no such log, 2 on a usage error. */
export function runLog(rest: string[], env: Env, io: LogOut = realOut, read: (p: string) => string = (p) => readFileSync(p, "utf8")): number {
  let list = false;
  let pathOnly = false;
  let timings = false;
  let id: string | undefined;
  for (const a of rest) {
    if (a === "--list") list = true;
    else if (a === "--path") pathOnly = true;
    else if (a === "--timings") timings = true;
    else if (a.startsWith("-")) { io.err(`mandu log: unknown option ${a}\n${LOG_USAGE.join("\n")}\n`); return 2; }
    else if (id === undefined) id = a;
    else { io.err(`mandu log: one session id at most\n${LOG_USAGE.join("\n")}\n`); return 2; }
  }
  const dir = launchLogDir(env);
  const logs = listLaunchLogs(env);
  if (logs.length === 0) {
    io.err(`mandu log: no launch log yet (launch logs are kept in ${dir})\n`);
    return 1;
  }
  if (list) {
    for (const e of logs) io.out(`${localStamp(e.startedAt)}  ${e.sessionId}  ${e.path}\n`);
    return 0;
  }
  if (timings && !pathOnly) return showTimings(id === undefined ? logs : matching(logs, id), id, io, read);
  const pick = id === undefined ? logs[0] : matching(logs, id)[0];
  if (pick === undefined) {
    io.err(`mandu log: no kept launch log for session ${id} (\`mandu log --list\` names the kept ones)\n`);
    return 1;
  }
  if (pathOnly) {
    io.out(`${pick.path}\n`);
    return 0;
  }
  let text: string;
  try {
    text = read(pick.path);
  } catch (e) {
    io.err(`mandu log: cannot read ${pick.path}: ${(e as Error).message}\n`);
    return 1;
  }
  io.out(printable(text));
  if (text !== "" && !text.endsWith("\n")) io.out("\n");
  return 0;
}

/** The kept logs of session `id`: the exact id, else the ones it is a prefix of. */
function matching(logs: LaunchLogEntry[], id: string): LaunchLogEntry[] {
  const exact = logs.filter((e) => e.sessionId === id);
  return exact.length > 0 ? exact : logs.filter((e) => e.sessionId.startsWith(id));
}

/**
 * `mandu log --timings`: how long each step of the last launches took
 * (runtime-instances.md §14.11), one column per launch, newest first, with
 * their median; with a session id, that launch's. A log written before the
 * timings existed, or one that cannot be read, is passed over.
 */
function showTimings(logs: LaunchLogEntry[], id: string | undefined, io: LogOut, read: (p: string) => string): number {
  const found: Array<{ label: string; timings: LaunchTimings }> = [];
  for (const e of logs) {
    if (found.length >= (id === undefined ? TIMINGS_SHOWN : 1)) break;
    let t: LaunchTimings | null = null;
    try { t = timingsFromLog(read(e.path)); } catch { /* passed over */ }
    if (t !== null) found.push({ label: localStamp(e.startedAt).slice(5, 16), timings: t });
  }
  if (found.length === 0) {
    io.err(id === undefined
      ? "mandu log: no kept launch log has its timings yet (an older Mandu did not keep them)\n"
      : `mandu log: no kept launch log for session ${id} has its timings\n`);
    return 1;
  }
  for (const l of formatTimingsTable(found)) io.out(`${l}\n`);
  return 0;
}
