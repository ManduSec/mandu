/**
 * openclaw-config-read — read the user's OpenClaw config the way OpenClaw
 * does: the path (`$OPENCLAW_CONFIG_PATH`, else `$OPENCLAW_STATE_DIR/
 * openclaw.json`, else `~/.openclaw/openclaw.json`), JSON5, every `$include`
 * resolved (openclaw-include.ts), and the files that went into it.
 * Mandu-new (no reference origin; the path order is OpenClaw's
 * config/paths.ts resolveCanonicalConfigPath).
 *
 * One reader for every place Mandu checks an attached Gateway's route
 * (docs/design/agents/openclaw-plugin.md §3.6, §8): `mandu openclaw install`
 * and its doctor check in the launcher, and the service's route check in the
 * dashboard (the pool, dashboard/src/supervisor/attachment-pool.ts). The
 * three files (this one, json5.ts, openclaw-include.ts) ship byte for byte in
 * both packages; the source is launcher/src/services/: change it, then run
 * `node scripts/copies/module-copies.mjs generate`.
 */
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { join, normalize, resolve } from "node:path";

import { parseJson5 } from "./json5.js";
import { IncludeError, resolveOpenclawIncludes, type IncludeFs } from "./openclaw-include.js";

type Json = Record<string, unknown>;
type Env = Record<string, string | undefined>;

/** Where the user's OpenClaw config lives (OpenClaw's own order). */
export function openclawConfigPath(env: Env, home: string = env["HOME"] || homedir()): string {
  return env["OPENCLAW_CONFIG_PATH"] || join(env["OPENCLAW_STATE_DIR"] || join(home, ".openclaw"), "openclaw.json");
}

/** Parse a config file's text: JSON5, which must hold an object. Throws. */
export function parseConfigObject(text: string): Json {
  const parsed = parseJson5(text);
  if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as Json;
  throw new Error("not a JSON object");
}

/** A config read: the file as written (`raw`), what OpenClaw runs
 *  (`effective`, includes resolved) and every file read for it (`files`: the
 *  main file first, then each include, absolute); or why it could not be. */
export type OpenclawConfigRead =
  | { ok: true; path: string; target: string; text: string; raw: Json; effective: Json; files: string[] }
  | { ok: false; path: string; error: string; absent?: true; files: string[] };

const nodeIncludeFs = (read: string[]): IncludeFs => ({
  realpath: (p) => realpathSync(p),
  lstat: (p) => lstatSync(p),
  stat: (p) => lstatSync(realpathSync(p)),
  readFile: (p) => {
    const abs = normalize(resolve(p));
    if (!read.includes(abs)) read.push(abs);
    return readFileSync(p, "utf8");
  },
});

/** Read the config at `path` as OpenClaw would. Never throws. */
export function readOpenclawConfig(path: string, env: Env, home: string = env["HOME"] || homedir()): OpenclawConfigRead {
  const main = normalize(resolve(path));
  const files = [main];
  let target = path;
  try {
    lstatSync(path);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    return code === "ENOENT"
      ? { ok: false, path, error: `no OpenClaw config at ${path}`, absent: true, files }
      : { ok: false, path, error: `could not read ${path}: ${(e as Error).message}`, files };
  }
  try {
    if (lstatSync(path).isSymbolicLink()) target = realpathSync(path);
  } catch { /* the read below says why */ }
  try {
    const text = readFileSync(path, "utf8");
    const raw = parseConfigObject(text);
    const effective = resolveOpenclawIncludes(raw, path, { env, home, fs: nodeIncludeFs(files) }) as Json;
    return { ok: true, path, target, text, raw, effective, files };
  } catch (e) {
    const msg = e instanceof IncludeError && normalize(resolve(e.includePath)) !== main
      ? `$include "${e.includePath}": ${e.message}`
      : (e as Error).message;
    return { ok: false, path, error: `could not read ${path}: ${msg}`, files };
  }
}
