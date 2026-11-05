/**
 * serve-unit — the systemd user unit `mandu serve` ships (runtime-instances.md
 * §4.1d, openclaw-plugin.md §3.2): its name, its text rendered with the
 * installed mandu's paths, the parse of a unit file back into what it runs,
 * and the decisions of `mandu serve install|start|stop|upgrade|uninstall`.
 *
 * Everything here is pure: no file, process or systemctl is touched, so each
 * rule is unit-tested over plain facts (test/unit/serve-unit.test.ts). The
 * effects live in serve-command.ts behind an injectable runner.
 *
 * The unit runs what the maintainer's hand-written unit ran since 2026-09
 * (and what a launch's autostart runs, arbiter.ts startArbiterInstance): the
 * dashboard as the supervisor of the arbiter (`DASHBOARD_AUTOSTART=arbiter`),
 * promoted at the account's rendezvous (`MANDU_PROMOTE=1`), ownerless
 * (`MANDU_OWNER_PID=none`), restarted by systemd when it exits
 * (`Restart=always`; the dashboard exits when its arbiter does, §4.1b).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { dirname, join } from "node:path";
import type { DaemonSpec } from "./services/layout.js";

/** The shipped unit's name. The auto-detection (stack-supervisor.ts) and the
 *  refusals name `mandu serve` for a stack this unit runs. */
export const SERVE_UNIT = "mandu.service";

/** The line that marks a unit file as written by `mandu serve install`: only
 *  such a file is rewritten by `upgrade` or removed by `uninstall`. */
export const SERVE_UNIT_MARKER = "# X-Mandu-Serve-Unit: 1";

type Env = Record<string, string | undefined>;

/** The variables a caller may set at install time that the unit carries
 *  (where the stack keeps its state and where the dashboard listens). */
export const SERVE_CARRIED_ENV = [
  "MANDU_HOME", "DASHBOARD_PORT", "DASHBOARD_HOST", "DASHBOARD_BASE_PATH", "DASHBOARD_ALLOW_HOSTS",
  // The model upstream of the proxy pool's proxies (openclaw-plugin.md §3.2,
  // attachment-pool.ts POOL_UPSTREAM_KEYS): where the Gateway's model calls
  // go after Mandu. A URL that carries credentials is never written into the
  // unit file (`carriedValueOk`); set it in a drop-in instead.
  "MANDU_UPSTREAM", "MANDU_UPSTREAM_LOCAL",
] as const;

/** Whether a carried variable's value may be written into the unit file:
 *  an upstream URL with a user or password in it may not. Pure. */
export function carriedValueOk(key: string, value: string): boolean {
  if (key !== "MANDU_UPSTREAM") return true;
  try {
    const u = new URL(value);
    return u.username === "" && u.password === "";
  } catch {
    return true;
  }
}

/** What the unit is rendered from. */
export interface ServeUnitInput {
  /** This mandu's release (named in the header, so a new release reads as a
   *  unit file to rewrite). */
  version: string;
  /** "npm" (an installed package) or "checkout" (a source checkout). */
  install: "npm" | "checkout";
  /** The package root (npm) or the checkout's root. */
  root: string;
  /** The absolute node that runs the dashboard (a user manager's PATH does
   *  not hold an nvm or Homebrew node). */
  node: string;
  /** How the layout starts the dashboard (services/layout.ts daemon()). */
  daemon: DaemonSpec;
  /** The stack's runtime dir: `%t/mandu` (systemd's $XDG_RUNTIME_DIR) when
   *  the account's default, else the literal path. */
  runtimeDir: string;
  /** The carried variables that were set (SERVE_CARRIED_ENV). */
  carried: Record<string, string>;
  /** The guide's URL (docs-url.ts). */
  docs: string;
}

/** The runtime dir as the unit spells it: `%t/mandu` for the account's
 *  default (`$XDG_RUNTIME_DIR/mandu`, what a user manager's %t is), else the
 *  literal `base`. Pure. */
export function unitRuntimeDir(base: string, source: "explicit" | "xdg" | "tmpdir" | "fallback"): string {
  return source === "xdg" ? "%t/mandu" : base;
}

/** The input for this mandu: the layout's dashboard daemon run by `node`,
 *  the env's carried variables. Pure. */
export function serveUnitInput(i: {
  version: string;
  install: "npm" | "checkout";
  root: string;
  node: string;
  daemon: DaemonSpec;
  runtimeDir: string;
  env: Env;
  docs: string;
}): ServeUnitInput {
  const carried: Record<string, string> = {};
  for (const k of SERVE_CARRIED_ENV) {
    const v = i.env[k];
    if (v !== undefined && v !== "" && carriedValueOk(k, v)) carried[k] = v;
  }
  return { version: i.version, install: i.install, root: i.root, node: i.node, daemon: i.daemon, runtimeDir: i.runtimeDir, carried, docs: i.docs };
}

/** Refuse a value systemd cannot carry on one line. */
function oneLine(s: string, what: string): string {
  if (/[\n\r\0]/.test(s)) throw new Error(`mandu serve: ${what} holds a line break or NUL, which a unit file cannot carry`);
  return s;
}

/** One ExecStart word, quoted: `\` and `"` escaped, `%` and `$` doubled
 *  (systemd expands specifiers and variables in ExecStart). Pure. */
export function execWord(s: string): string {
  return `"${oneLine(s, "a command word").replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/%/g, "%%").replace(/\$/g, "$$$$")}"`;
}

/** One `Environment=` assignment, quoted: `%` doubled (specifiers are
 *  expanded there too; `$` is not). `raw` keeps a specifier such as `%t`. Pure. */
export function envAssignment(key: string, value: string, raw = false): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new Error(`mandu serve: '${key}' is not a variable name`);
  const v = oneLine(value, key).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return `Environment="${key}=${raw ? v : v.replace(/%/g, "%%")}"`;
}

/** The PATH the unit gives the dashboard: node's own folder first (it spawns
 *  git and the other daemons), then the usual system folders. Pure. */
export function unitPath(node: string): string {
  const dirs = [dirname(node), "/usr/local/bin", "/usr/bin", "/bin"];
  return [...new Set(dirs)].join(":");
}

/**
 * The unit file's text. Deterministic (no time in it), so the file on disk
 * equals a fresh render exactly when nothing changed: the node, the paths,
 * the release, or a carried variable. Pure.
 */
export function renderServeUnit(u: ServeUnitInput): string {
  const cmd = u.daemon.cmd === "node" ? u.node : u.daemon.cmd;
  const where = u.install === "npm" ? `the npm package at ${u.root}` : `the source checkout at ${u.root}`;
  const env: string[] = [
    envAssignment("PATH", unitPath(u.node)),
    envAssignment("MANDU_RUNTIME_DIR", u.runtimeDir, u.runtimeDir.startsWith("%t/")),
    envAssignment("MANDU_PROMOTE", "1"),
    envAssignment("MANDU_OWNER_PID", "none"),
    envAssignment("DASHBOARD_AUTOSTART", "arbiter"),
    envAssignment("MANDU_SERVE", "1"),
    ...Object.keys(u.daemon.env).sort().map((k) => envAssignment(k, u.daemon.env[k]!)),
    ...Object.keys(u.carried).sort().map((k) => envAssignment(k, u.carried[k]!)),
  ];
  return [
    `# ${SERVE_UNIT}: the resident Mandu service, written by \`mandu serve install\`.`,
    SERVE_UNIT_MARKER,
    `# From mandu ${oneLine(u.version, "the release")}, ${oneLine(where, "the install path")}.`,
    "# `mandu serve upgrade` rewrites this file, so an edit here is lost: put",
    `# settings of your own in a drop-in (systemctl --user edit ${SERVE_UNIT}).`,
    "#",
    "# The dashboard runs as the supervisor of the arbiter, at this account's",
    "# Mandu rendezvous; launches (mandu claude, ...) attach to that arbiter.",
    "[Unit]",
    "Description=Mandu protection service (arbiter and dashboard)",
    `Documentation=${oneLine(u.docs, "the docs URL")}`,
    "",
    "[Service]",
    "Type=simple",
    // Taken whole, unquoted (a space is part of the path); `%` doubled.
    `WorkingDirectory=${oneLine(u.daemon.cwd, "the working directory").replace(/%/g, "%%")}`,
    `ExecStart=${[cmd, ...u.daemon.args].map(execWord).join(" ")}`,
    ...env,
    "Restart=always",
    "RestartSec=2",
    // The dashboard gets the SIGTERM and stops its arbiter itself (graceful:
    // the instance dir removed, `current` cleared); what is left gets the
    // SIGKILL at the timeout.
    "KillMode=mixed",
    "TimeoutStopSec=30",
    "",
    "[Install]",
    "WantedBy=default.target",
    "",
  ].join("\n");
}

/** Undo one quoted or bare word of a unit file (the forms renderServeUnit
 *  writes, and plain words). `exec` also undoubles `$$`. Pure. */
function unquoteWords(s: string, exec: boolean): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < s.length) {
    while (i < s.length && /\s/.test(s[i]!)) i++;
    if (i >= s.length) break;
    let w = "";
    if (s[i] === '"') {
      i++;
      while (i < s.length && s[i] !== '"') {
        if (s[i] === "\\" && i + 1 < s.length) { w += s[i + 1]; i += 2; } else { w += s[i]; i++; }
      }
      i++;
    } else {
      while (i < s.length && !/\s/.test(s[i]!)) { w += s[i]; i++; }
    }
    w = w.replace(/%%/g, "\0pct\0");
    if (exec) w = w.replace(/\$\$/g, "$");
    out.push(w);
  }
  return out;
}

/** What a unit file runs: its ExecStart words, its WorkingDirectory and its
 *  Environment, with `%%` back to `%` and other specifiers left as written
 *  (`%t`), plus whether `mandu serve install` wrote it. Pure. */
export interface ParsedUnit {
  ours: boolean;
  execStart: string[];
  workingDirectory: string | null;
  environment: Record<string, string>;
  restart: string | null;
}

export function parseUnitFile(text: string): ParsedUnit {
  const pct = (s: string): string => s.replace(/\0pct\0/g, "%");
  let section = "";
  const parsed: ParsedUnit = { ours: text.split("\n").includes(SERVE_UNIT_MARKER), execStart: [], workingDirectory: null, environment: {}, restart: null };
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    const sec = /^\[(.+)\]$/.exec(line);
    if (sec) { section = sec[1]!; continue; }
    if (section !== "Service") continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    if (key === "ExecStart") parsed.execStart = unquoteWords(value, true).map(pct);
    else if (key === "WorkingDirectory") parsed.workingDirectory = value.replace(/^[-!+]+/, "").replace(/%%/g, "%") || null;
    else if (key === "Restart") parsed.restart = value;
    else if (key === "Environment") {
      for (const w of unquoteWords(value, false)) {
        const i = w.indexOf("=");
        if (i > 0) parsed.environment[w.slice(0, i)] = pct(w.slice(i + 1));
      }
    }
  }
  return parsed;
}

/** Expand the specifiers a user manager would in an Environment value
 *  (`%t` its runtime dir, `%h` the home, `%%` a percent sign); others are
 *  left as written. Pure. */
export function expandSpecifiers(value: string, env: Env): string {
  return value.replace(/%([th%])/g, (m, c: string) => (c === "%" ? "%" : c === "t" ? env["XDG_RUNTIME_DIR"] ?? m : env["HOME"] ?? m));
}

/** Where a user unit file goes: `$XDG_CONFIG_HOME/systemd/user`, else
 *  `~/.config/systemd/user`. Null with neither. Pure. */
export function unitFilePath(env: Env): string | null {
  const cfg = env["XDG_CONFIG_HOME"] || (env["HOME"] ? join(env["HOME"], ".config") : null);
  return cfg ? join(cfg, "systemd", "user", SERVE_UNIT) : null;
}

// ── the decisions ─────────────────────────────────────────────────────────

/** Whether systemd --user can run the unit here. */
export type ServeHost =
  | { kind: "ok" }
  /** macOS: launchd is planned, not built. */
  | { kind: "darwin" }
  /** No user manager answers (a container, WSL without systemd, a host
   *  without systemd). `why` is systemctl's own words. */
  | { kind: "no-systemd"; why: string }
  | { kind: "other-os"; platform: string };

/** Classify the host from the platform and one `systemctl --user show -p
 *  Version` (127 = no systemctl at all). Pure. */
export function serveHost(platform: string, probe: { code: number; stderr: string } | null): ServeHost {
  if (platform === "darwin") return { kind: "darwin" };
  if (platform !== "linux") return { kind: "other-os", platform };
  if (probe === null || probe.code === 127) return { kind: "no-systemd", why: "systemctl is not installed" };
  if (probe.code !== 0) return { kind: "no-systemd", why: probe.stderr.trim().split("\n")[0] || `systemctl --user exited ${probe.code}` };
  return { kind: "ok" };
}

/** The refusal for a host the unit cannot run on, in the user's words. Pure. */
export function hostRefusal(h: Exclude<ServeHost, { kind: "ok" }>): string {
  switch (h.kind) {
    case "darwin":
      return "mandu serve: not yet on macOS (a launchd agent is planned). Meanwhile `mandu dashboard` keeps the " +
        "dashboard running in the background, and each launch starts the protection service it needs.";
    case "other-os":
      return `mandu serve: runs on Linux with systemd (this is ${h.platform}).`;
    case "no-systemd":
      return `mandu serve: there is no systemd user manager here (${h.why}), so there is nothing to install the service into. ` +
        "In WSL turn systemd on ([boot] systemd=true in /etc/wsl.conf, then wsl --shutdown); in a container, or on a host " +
        "without systemd, run `mandu dashboard` instead: it keeps the dashboard running, and each launch starts the " +
        "protection service it needs.";
  }
}

/** The facts a start (or the start an install or upgrade ends with) decides on. */
export interface StartFacts {
  /** Another systemd service already runs this stack (stack-supervisor.ts
   *  stackService), named; null when none or when it is ours. */
  otherService: string | null;
  /** Resident daemons of this stack running outside the unit (a launch's
   *  autostart, `mandu dashboard`): their pids. */
  outside: readonly number[];
  /** `mandu` sessions using the stack (liveLaunchersOn). */
  sessions: readonly number[];
  /** --force: stop the outside daemons even under live sessions. */
  force: boolean;
}

export type StartPlan =
  /** Another service runs this stack: two services would fight over it. */
  | { kind: "refuse-other-service"; unit: string }
  /** The stack runs outside the unit and sessions use it: starting would cut
   *  them off. Nothing is started. */
  | { kind: "defer"; outside: readonly number[]; sessions: readonly number[] }
  /** Stop the outside daemons first (`stopOutside`), then start the unit. */
  | { kind: "start"; stopOutside: readonly number[] };

/**
 * Start the unit, unless another service already runs the stack (refused),
 * or the stack's services run outside the unit while sessions use them (the
 * session check the launch's release restart uses, §4.1: deferred, `--force`
 * goes on). With no session, the outside daemons are stopped first, so the
 * unit owns the whole stack rather than adopting an arbiter it cannot
 * restart (§4.1b). Pure.
 */
export function planStart(f: StartFacts): StartPlan {
  if (f.otherService !== null) return { kind: "refuse-other-service", unit: f.otherService };
  if (f.outside.length > 0 && f.sessions.length > 0 && !f.force) return { kind: "defer", outside: f.outside, sessions: f.sessions };
  return { kind: "start", stopOutside: f.outside };
}

/** The running stack's code against this mandu (arbiter-version.ts verdict). */
export type CodeVerdict = "match" | "unknown" | "older" | "newer" | "other" | "build" | "not-running";

/** The facts an upgrade decides on. */
export interface UpgradeFacts {
  /** The unit file on disk: absent, written by mandu serve, or someone else's. */
  onDisk: "absent" | "ours" | "foreign";
  /** The fresh render differs from the file on disk. */
  unitChanged: boolean;
  /** The unit's ActiveState is `active`. */
  active: boolean;
  /** The stack's arbiter against this mandu. */
  verdict: CodeVerdict;
  /** The arbiter answering is not the unit's own process (adopted). */
  arbiterOutside: boolean;
  sessions: readonly number[];
  force: boolean;
  /** --wait: wait for the sessions to end instead of deferring. */
  wait: boolean;
}

export type UpgradePlan =
  | { kind: "not-installed" }
  | { kind: "foreign" }
  /** The service already runs this mandu's code from a current unit file. */
  | { kind: "current"; write: boolean }
  /** A restart is due but sessions use the stack: the file is written (it
   *  takes effect at the next start), the restart deferred. */
  | { kind: "defer"; write: boolean; sessions: readonly number[]; why: string }
  | { kind: "wait"; write: boolean; sessions: readonly number[]; why: string }
  | { kind: "restart"; write: boolean; why: string };

/**
 * `mandu serve upgrade`: rewrite the unit file when the render changed, and
 * restart the service when it does not run this mandu's code (the arbiter's
 * release or build differs, the arbiter is not the unit's own, the unit file
 * changed, or the unit is not running) — only when no `mandu` session uses
 * the stack, the deferral of the launch's release restart (§4.1): deferred,
 * or waited out with --wait; --force restarts anyway. Pure.
 */
export function planUpgrade(f: UpgradeFacts): UpgradePlan {
  if (f.onDisk === "absent") return { kind: "not-installed" };
  if (f.onDisk === "foreign") return { kind: "foreign" };
  const write = f.unitChanged;
  const why =
    !f.active ? "the service is not running" :
    f.verdict === "not-running" ? "the service's arbiter does not answer" :
    f.verdict !== "match" && f.verdict !== "unknown" ? "the service runs other code than this mandu" :
    f.arbiterOutside ? "the stack's arbiter is not the service's own process" :
    f.unitChanged ? "the unit file changed" :
    f.force ? "--force" : null;
  if (why === null) return { kind: "current", write };
  if (f.sessions.length > 0 && !f.force && f.active) {
    return f.wait ? { kind: "wait", write, sessions: f.sessions, why } : { kind: "defer", write, sessions: f.sessions, why };
  }
  return { kind: "restart", write, why };
}

/** A stop or uninstall would cut live sessions off: refused without --force. Pure. */
export function stopBlockedBy(active: boolean, sessions: readonly number[], force: boolean): readonly number[] {
  return active && !force ? sessions : [];
}
