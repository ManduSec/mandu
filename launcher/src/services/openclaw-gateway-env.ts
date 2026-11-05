/**
 * openclaw-gateway-env — what an OpenClaw Gateway's environment says about
 * its Azure OpenAI endpoint (docs/design/agents/model-wires.md §9.1).
 *
 * Mandu-new (no reference origin). ONE MODULE, TWO COPIES: the source is
 * launcher/src/services/openclaw-gateway-env.ts (install and the doctor); the
 * service's route check reads it in the dashboard
 * (dashboard/src/openclaw/openclaw-gateway-env.ts). Change it, then run
 * `node scripts/copies/module-copies.mjs generate`.
 *
 * WHY. OpenClaw's Azure OpenAI client reads AZURE_OPENAI_BASE_URL, then
 * AZURE_OPENAI_RESOURCE_NAME, BEFORE the provider's `baseUrl` (@openclaw/ai
 * `resolveAzureConfig`, 2026.7.1-2 to 2026.10.7): set in the Gateway's
 * environment, every Azure call goes there, around Mandu's route. Mandu does
 * not start a resident Gateway (Route 1), so it reads where that
 * environment comes from, for the Gateway whose config is the one checked:
 *   - the running Gateway's own environment, `/proc/<pid>/environ` (same
 *     user, no privilege): every process of this user that is an OpenClaw
 *     Gateway (`openclaw … gateway …`, or the `openclaw-gateway` title
 *     OpenClaw sets) and whose environment resolves to this config
 *     (OPENCLAW_CONFIG_PATH, else OPENCLAW_STATE_DIR, else HOME, as OpenClaw
 *     resolves it). A process's environ is its environment at exec; what
 *     OpenClaw loads later comes from the files below;
 *   - the Gateway's systemd user unit (`openclaw-gateway*.service` in the
 *     user's unit directory), installed whether or not it runs: its
 *     `Environment=` assignments and `EnvironmentFile=` files, when the unit's
 *     own environment resolves to this config (the next start reads them);
 *   - OpenClaw's global dotenv files (`<config dir>/.env`,
 *     `~/.openclaw/.env`, `$OPENCLAW_STATE_DIR/.env`,
 *     `~/.config/openclaw/gateway.env`), which OpenClaw loads where the
 *     variable is unset.
 * The config's own `env` block is the route check's to read (pure).
 *
 * FAIL-CLOSED. Where a running Gateway's environment cannot be read (no
 * /proc: not Linux; a Gateway process whose environ is unreadable), the
 * answer is `verified: false`: the route is "not verified", never "routed".
 * No Gateway running and no unit is verified with nothing set: the route
 * check runs again, and a Gateway started later is read then.
 *
 * The values are never kept: only the variable names and where they are set.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";

import { openclawConfigPath } from "./openclaw-config-read.js";
import type { GatewayEnvFacts } from "../attachment-contract.js";

type Env = Record<string, string | undefined>;

/** The variables OpenClaw's Azure client reads before a provider's baseUrl. */
export const AZURE_ENDPOINT_VARS = ["AZURE_OPENAI_BASE_URL", "AZURE_OPENAI_RESOURCE_NAME"] as const;

/** The I/O the reader does (real by default; tests pass a fake tree). */
export interface GatewayEnvIo {
  /** The pids to look at, or null when this system has no /proc to list. */
  listPids(): number[] | null;
  /** The owner uid of a process, or null (gone). */
  uidOf(pid: number): number | null;
  /** `/proc/<pid>/cmdline` (NUL-separated), or null. */
  readCmdline(pid: number): string | null;
  /** `/proc/<pid>/environ` (NUL-separated), or null when unreadable. */
  readEnviron(pid: number): string | null;
  /** A file's text, or null. */
  readFile(path: string): string | null;
  /** A directory's entries, or null. */
  listDir(path: string): string[] | null;
  /** This user's uid (undefined: not a POSIX host). */
  uid: number | undefined;
}

export function realGatewayEnvIo(): GatewayEnvIo {
  const text = (p: string): string | null => { try { return readFileSync(p, "utf8"); } catch { return null; } };
  return {
    listPids: () => {
      if (process.platform !== "linux") return null;
      try { return readdirSync("/proc").filter((n) => /^\d+$/.test(n)).map(Number); } catch { return null; }
    },
    uidOf: (pid) => { try { return statSync(`/proc/${pid}`).uid; } catch { return null; } },
    readCmdline: (pid) => text(`/proc/${pid}/cmdline`),
    readEnviron: (pid) => text(`/proc/${pid}/environ`),
    readFile: text,
    listDir: (p) => { try { return readdirSync(p); } catch { return null; } },
    uid: process.getuid?.(),
  };
}

/** NUL-separated `KEY=value` entries as an env. Pure. */
export function parseEnviron(raw: string): Env {
  const out: Env = {};
  for (const e of raw.split("\0")) {
    const i = e.indexOf("=");
    if (i > 0) out[e.slice(0, i)] = e.slice(i + 1);
  }
  return out;
}

/**
 * Whether a process's argv is an OpenClaw Gateway: the title OpenClaw sets
 * (`openclaw-gateway`), or an `openclaw` program (`openclaw`, `openclaw.mjs`,
 * `openclaw-<version>`) followed by `gateway` and then `run`, `start` or
 * nothing else that is a subcommand (`gateway status`, `stop`, `install`
 * are short-lived clients, not the Gateway). Pure.
 */
export function isGatewayArgv(argv: readonly string[]): boolean {
  if (argv.length === 0) return false;
  const base = (s: string): string => s.slice(s.lastIndexOf("/") + 1);
  if (/^openclaw-gateway\b/.test(base(argv[0]!))) return true;
  const prog = argv.findIndex((a) => /^openclaw(?:\.mjs|-[0-9][\w.-]*)?$/.test(base(a)));
  if (prog < 0) return false;
  // `gateway` is the command: every word before it is a global option or
  // its value (`--profile work gateway run`), not another command's word.
  const after = argv.slice(prog + 1);
  const g = after.indexOf("gateway");
  if (g < 0) return false;
  for (let i = 0; i < g; i++) {
    const flagValue = i > 0 && after[i - 1]!.startsWith("-") && !after[i - 1]!.includes("=");
    if (!after[i]!.startsWith("-") && !flagValue) return false;
  }
  const sub = after.slice(g + 1).find((a) => !a.startsWith("-"));
  return sub === undefined || sub === "run" || sub === "start";
}

/** The Azure endpoint variables an env sets (non-empty). Pure. */
function azureSet(env: Env): string[] {
  return AZURE_ENDPOINT_VARS.filter((k) => (env[k] ?? "").trim() !== "");
}

/** `KEY=value` lines of a dotenv or EnvironmentFile (`export`, quotes,
 *  comments). Pure. */
export function parseEnvFile(text: string): Env {
  const out: Env = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    out[m[1]!] = m[2]!.trim().replace(/^(["'])(.*)\1$/, "$2").trim();
  }
  return out;
}

/** A systemd unit's `[Service]` environment: its `Environment=` assignments
 *  (several per line, quoted or not) and its `EnvironmentFile=` paths
 *  (`-` prefix: optional; `%h` is the home). Pure. */
export function parseUnitEnvironment(text: string, home: string): { env: Env; files: string[] } {
  const env: Env = {};
  const files: string[] = [];
  // Continuation lines joined first.
  const lines = text.replace(/\\\r?\n/g, " ").split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    const m = /^(Environment|EnvironmentFile)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    if (m[1] === "EnvironmentFile") {
      const p = m[2]!.trim().replace(/^-/, "").replace(/%h/g, home);
      if (p !== "") files.push(p);
      continue;
    }
    const re = /"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+)/g;
    let t: RegExpExecArray | null;
    while ((t = re.exec(m[2]!)) !== null) {
      const word = (t[1] ?? t[2] ?? t[3] ?? "").replace(/%h/g, home);
      const i = word.indexOf("=");
      if (i > 0) env[word.slice(0, i)] = word.slice(i + 1);
    }
  }
  return { env, files };
}

/** The config an environment's OpenClaw reads (absolute). */
function configOf(env: Env, fallbackHome: string, cwd?: string): string {
  const home = env["HOME"] || fallbackHome;
  const p = openclawConfigPath(env, home).replace(/^~(?=\/)/, home);
  return isAbsolute(p) ? resolve(p) : resolve(cwd ?? home, p);
}

/**
 * Where the Azure endpoint variables are set for the Gateway that reads
 * `configPath`, as `<NAME> (<where>)`, and whether a running Gateway's
 * environment could be read. `env`: the reader's own environment (HOME,
 * XDG_CONFIG_HOME, OPENCLAW_STATE_DIR for the dotenv files). Never a value.
 */
export function gatewayAzureEnv(configPath: string, env: Env, io: GatewayEnvIo = realGatewayEnvIo()): GatewayEnvFacts {
  const home = env["HOME"] || homedir();
  const target = resolve(configPath);
  const set: string[] = [];
  const add = (names: readonly string[], where: string): void => {
    for (const n of names) {
      const s = `${n} (${where})`;
      if (!set.includes(s)) set.push(s);
    }
  };

  // OpenClaw's global dotenv files.
  const dotenvs = new Set([
    join(dirname(target), ".env"),
    join(home, ".openclaw", ".env"),
    ...(env["OPENCLAW_STATE_DIR"] ? [join(env["OPENCLAW_STATE_DIR"], ".env")] : []),
    join(home, ".config", "openclaw", "gateway.env"),
  ]);
  for (const f of dotenvs) {
    const t = io.readFile(f);
    if (t !== null) add(azureSet(parseEnvFile(t)), f);
  }

  // The Gateway's systemd user unit(s), running or not.
  const unitDir = join(env["XDG_CONFIG_HOME"] || join(home, ".config"), "systemd", "user");
  for (const name of io.listDir(unitDir) ?? []) {
    if (!/^openclaw-gateway[\w@.-]*\.service$/.test(name)) continue;
    const path = join(unitDir, name);
    const text = io.readFile(path);
    if (text === null) continue;
    const unit = parseUnitEnvironment(text, home);
    const fileEnv: Env = {};
    for (const f of unit.files) {
      const t = io.readFile(f);
      if (t !== null) Object.assign(fileEnv, parseEnvFile(t));
    }
    const merged: Env = { HOME: home, ...fileEnv, ...unit.env };
    if (configOf(merged, home) !== target) continue;
    add(azureSet(unit.env), `${path}, Environment=`);
    for (const f of unit.files) {
      const t = io.readFile(f);
      if (t !== null) add(azureSet(parseEnvFile(t)), `${f}, the EnvironmentFile of ${name}`);
    }
  }

  // The running Gateway(s) of this config.
  const pids = io.listPids();
  if (pids === null) {
    return { verified: false, why: "Mandu cannot read a running OpenClaw Gateway's environment on this system (no /proc)", set };
  }
  let unreadable: number | null = null;
  for (const pid of pids) {
    if (io.uid !== undefined && io.uidOf(pid) !== io.uid) continue;
    const cmd = io.readCmdline(pid);
    if (cmd === null || !isGatewayArgv(cmd.split("\0").filter((a) => a !== ""))) continue;
    const raw = io.readEnviron(pid);
    if (raw === null) { unreadable = pid; continue; }
    const penv = parseEnviron(raw);
    if (configOf(penv, home) !== target) continue;
    add(azureSet(penv), `the running Gateway's environment, pid ${pid}`);
  }
  if (unreadable !== null) {
    return { verified: false, why: `the environment of OpenClaw Gateway pid ${unreadable} cannot be read`, set };
  }
  return { verified: true, set };
}
