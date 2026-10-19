/**
 * eval-out — where an evaluation run writes when the operator names no
 * `--out` (docs/design/architecture/on-disk-layout.md §9 decision 3): a fresh run dir
 * under the path table's `eval-runs` (`~/.mandu/runs/eval`, moved by
 * MANDU_HOME). An explicit `--out` still wins, verbatim.
 *
 * The run id is `<UTC timestamp>-<suite>-<6 hex>`: it sorts by start time,
 * names the runner, and the random tail keeps two runs started in the same
 * second apart. eval/agentdojo/eval_out.py mints the same shape.
 *
 * Only results go in the run dir. A default one is inside the Mandu home,
 * which the agent may not reach, and is too deep for a Unix socket path. So
 * everything the agent under test touches, sockets included, lives in a short
 * per-leg work dir outside every Mandu home (paired/leg-work.ts).
 *
 * Mandu-new (no reference origin).
 */
import { randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { manduPath, type ManduPathEnv } from "./generated/mandu-paths.js";

/** The path table's `eval-runs` for `env` and `home`. Pure. */
export function evalRunsDir(env: ManduPathEnv = process.env, home: string = homedir()): string {
  return manduPath("eval-runs", env, home);
}

/** `<UTC yyyymmddThhmmssZ>-<suite>-<6 hex>`. Pure given `now` and `random`. */
export function mintRunId(suite: string, now: Date = new Date(), random: string = randomBytes(3).toString("hex")): string {
  if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(suite)) throw new Error(`Invalid run suite name: ${JSON.stringify(suite)}`);
  if (!/^[0-9a-f]{6}$/.test(random)) throw new Error("Invalid run id random tail");
  const stamp = now.toISOString().replace(/\.\d{3}Z$/, "Z").replace(/[-:]/g, "");
  return `${stamp}-${suite}-${random}`;
}

export interface EvalOut {
  /** Absolute run dir. The runner creates it (non-recursively, 0700), so an
   *  existing one is refused: each run is its own evidence record. */
  dir: string;
  /** True when no `--out` was given and the dir is the default. */
  defaulted: boolean;
}

export interface EvalOutOptions {
  env?: ManduPathEnv;
  home?: string;
  now?: Date;
  random?: string;
}

/** Resolve a runner's output dir. With `out`, that path (resolved against the
 *  cwd). Without, `<eval-runs>/<run id>`, creating `eval-runs` and any missing
 *  parent (the Mandu home, `runs/`) owner-only (0700). */
export function resolveEvalOut(out: string | undefined, suite: string, opts: EvalOutOptions = {}): EvalOut {
  if (out) return { dir: resolve(out), defaulted: false };
  const root = evalRunsDir(opts.env ?? process.env, opts.home ?? homedir());
  mkdirSync(root, { recursive: true, mode: 0o700 });
  return { dir: join(root, mintRunId(suite, opts.now, opts.random)), defaulted: true };
}

/** The line a runner prints before it starts. */
export function outputBanner(out: EvalOut): string {
  return `Output: ${out.dir}${out.defaulted ? " (default; pass --out <dir> to choose)" : ""}`;
}
