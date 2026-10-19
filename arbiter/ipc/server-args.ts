/**
 * server-args — the arbiter daemon's command line (Mandu-new, no reference
 * origin; docs/design/architecture/on-disk-layout.md §5).
 *
 *   server-main.ts [<socket>] [--symbol-db <path>] [--event-dir <path>]
 *                  [--classifier <json argv>] [--landlock-apply <path>]
 *                  [--net-guard <path>] [--seed-from <path> [--seed-policy <path>]]
 *
 * The two stores' paths come from flags, which only Mandu's own spawners pass
 * (the launcher's per-launch arbiter, the dashboard supervisor's test tenant).
 * Absent, each is the path table's entry under the Mandu home
 * (`${MANDU_HOME:-~/.mandu}/state/mandu.db`, `…/events`). No environment
 * variable moves a single store: a session that can set its own environment
 * must not be able to point the arbiter somewhere else.
 *
 * The policy classifier (confidentiality-plan-14 §14.3) is found the same
 * way, never from the environment: `--classifier` is the command the arbiter
 * runs for a names-only model run, as a JSON array of strings (`["/usr/bin/
 * node", "--import", "file:///…/tsx/…", "/…/classify-main.ts"]`), and
 * `--landlock-apply` the absolute path of `mandu-landlock-apply`, which
 * confines the classifier's network. The dashboard supervisor and the
 * launcher pass them from their own layout; without `--classifier` the model
 * ops answer "not available in this install".
 *
 * `--net-guard` is the absolute path of `mandu-net-guard`, the address guard
 * every prompt filter plugin runs under (confidentiality-plan-15 §4.3, §12
 * 2026-10-03); `--landlock-apply` also confines the plugins. Without
 * `--net-guard` no plugin runs (its `on_error` decides).
 *
 * `--seed-from` names the resident arbiter's store to seed this one's from,
 * read only (`mandu why` with no Mandu running: db/store-seed.ts), and
 * `--seed-policy` the policy file whose content in force is carried over;
 * only the launcher passes them, to its temporary arbiter, and server-main
 * refuses them on any other (a promoted or socket-less start).
 *
 * `--flag value` and `--flag=value` both work. Every other argument keeps its
 * old meaning: the first one is the socket path, bound verbatim. A flag with
 * no value, or an empty one, is refused. Pure.
 */
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";

import { manduPath, type ManduPathEnv } from "../src/generated/mandu-paths.js";

export interface ServerArgs {
  /** The explicit socket path (first plain argument), if any. */
  socketPath?: string;
  /** `--symbol-db`, made absolute, if given. */
  symbolDb?: string;
  /** `--event-dir`, made absolute, if given. */
  eventDir?: string;
  /** `--classifier`: the policy classifier's argv, if given. */
  classifier?: string[];
  /** `--landlock-apply`: the applier's absolute path, if given. */
  landlockApply?: string;
  /** `--net-guard`: `mandu-net-guard`'s absolute path, if given. */
  netGuard?: string;
  /** `--seed-from`: the store to seed this one's from (read only), made absolute. */
  seedFrom?: string;
  /** `--seed-policy`: the policy file the seeded store's content in force is of. */
  seedPolicy?: string;
}

const PATH_FLAGS = { "--symbol-db": "symbolDb", "--event-dir": "eventDir", "--seed-from": "seedFrom", "--seed-policy": "seedPolicy" } as const;
type PathFlag = keyof typeof PATH_FLAGS;
const OTHER_FLAGS = ["--classifier", "--landlock-apply", "--net-guard"] as const;
type OtherFlag = (typeof OTHER_FLAGS)[number];

function isPathFlag(s: string): s is PathFlag {
  return Object.prototype.hasOwnProperty.call(PATH_FLAGS, s);
}

function isOtherFlag(s: string): s is OtherFlag {
  return (OTHER_FLAGS as readonly string[]).includes(s);
}

const isFlag = (s: string): boolean => isPathFlag(s) || isOtherFlag(s);

export class ServerArgsError extends Error {
  constructor(message: string) {
    super(`${message} (usage: server-main.ts [<socket>] [--symbol-db <path>] [--event-dir <path>] [--classifier <json argv>] [--landlock-apply <path>] [--net-guard <path>] [--seed-from <path> [--seed-policy <path>]])`);
    this.name = "ServerArgsError";
  }
}

/** `--classifier`'s value: a JSON array of 1 to 32 non-empty strings without
 *  NUL, the first one an absolute path or a bare command name. Pure. */
export function parseClassifierArgv(value: string): string[] {
  let v: unknown;
  try { v = JSON.parse(value); } catch { throw new ServerArgsError("--classifier needs a JSON array of strings"); }
  if (!Array.isArray(v) || v.length === 0 || v.length > 32 || !v.every((x) => typeof x === "string" && x !== "" && !x.includes("\u0000"))) {
    throw new ServerArgsError("--classifier needs a JSON array of 1 to 32 non-empty strings");
  }
  const first = v[0] as string;
  if (!isAbsolute(first) && !/^[A-Za-z0-9._-]+$/.test(first)) throw new ServerArgsError("--classifier's command must be an absolute path or a command name");
  return v as string[];
}

/** Parse `argv` (process.argv.slice(2)). Relative store paths resolve
 *  against `cwd`. Throws ServerArgsError on a flag without a value or a flag
 *  given twice. */
export function parseServerArgs(argv: readonly string[], cwd: string = process.cwd()): ServerArgs {
  const out: ServerArgs = {};
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const eq = a.indexOf("=");
    const name = eq > 0 ? a.slice(0, eq) : a;
    if (!isFlag(name)) {
      positional.push(a);
      continue;
    }
    let value: string | undefined;
    if (eq > 0) value = a.slice(eq + 1);
    else {
      value = argv[i + 1];
      i++;
    }
    if (value === undefined || value === "" || (eq < 0 && isFlag(value))) {
      throw new ServerArgsError(`${name} needs ${name === "--classifier" ? "a JSON argv" : "a path"}`);
    }
    if (name === "--classifier") {
      if (out.classifier !== undefined) throw new ServerArgsError(`${name} given twice`);
      out.classifier = parseClassifierArgv(value);
      continue;
    }
    if (name === "--landlock-apply") {
      if (out.landlockApply !== undefined) throw new ServerArgsError(`${name} given twice`);
      if (!isAbsolute(value)) throw new ServerArgsError(`${name} needs an absolute path`);
      out.landlockApply = value;
      continue;
    }
    if (name === "--net-guard") {
      if (out.netGuard !== undefined) throw new ServerArgsError(`${name} given twice`);
      if (!isAbsolute(value)) throw new ServerArgsError(`${name} needs an absolute path`);
      out.netGuard = value;
      continue;
    }
    const key = PATH_FLAGS[name as PathFlag];
    if (out[key] !== undefined) throw new ServerArgsError(`${name} given twice`);
    out[key] = isAbsolute(value) ? value : resolve(cwd, value);
  }
  if (out.seedPolicy !== undefined && out.seedFrom === undefined) throw new ServerArgsError("--seed-policy needs --seed-from");
  if (positional.length > 0) out.socketPath = positional[0];
  return out;
}

/** The stores the daemon opens: the flags, else the table's defaults under
 *  `MANDU_HOME` (else `$HOME/.mandu`). */
export function resolveStorePaths(
  args: Pick<ServerArgs, "symbolDb" | "eventDir">,
  env: ManduPathEnv = process.env,
  home: string = env["HOME"] || homedir(),
): { symbolDb: string; eventDir: string } {
  return {
    symbolDb: args.symbolDb ?? manduPath("symbol-db", env, home),
    eventDir: args.eventDir ?? manduPath("events", env, home),
  };
}
