/**
 * services/openclaw-include — resolve `$include` in the user's
 * `openclaw.json` the way OpenClaw does, so the launch-time model check
 * (agent-model-route.ts), the model allowlist and the memory-search fence
 * (agent-config.ts) read the config OpenClaw would run, and the per-run
 * config Mandu writes carries it with no `$include` left in it.
 *
 * WHY the launcher writes the RESOLVED doc: the per-run config lives in the
 * scope run dir (OPENCLAW_CONFIG_PATH points there), and OpenClaw resolves a
 * relative `$include` against the directory of the file that names it, so a
 * written `$include` would no longer find its files. Writing the resolved doc
 * also means the config OpenClaw runs is exactly the one Mandu checked: a
 * detail this module reads differently from OpenClaw can cost the user a
 * setting, never let a model go around the check.
 *
 * SEMANTICS (read from OpenClaw's src/config/includes.ts in the published
 * 2026.7.1 and 2026.9.6 packages, which agree on every point below):
 *   - `$include` may sit in any object, at any depth, also inside arrays;
 *     its value is one path string or an array of path strings;
 *   - a relative path resolves against the directory of the file that names
 *     it (an included file's own includes resolve against ITS directory);
 *   - every include must stay inside the main config's directory, or inside
 *     a root listed in OPENCLAW_INCLUDE_ROOTS (`:`-separated), lexically and
 *     after symlinks (realpath);
 *   - the file must be a regular file of at most 2 MiB with one link (no
 *     hardlinks); it is parsed as JSON5 and its own includes are resolved;
 *   - an array of includes merges left to right starting from `{}`; sibling
 *     keys beside `$include` are merged over the included content (which
 *     must then be an object). The merge: objects recursively, arrays
 *     concatenate, anything else the later value wins; `__proto__`,
 *     `constructor` and `prototype` keys are skipped;
 *   - a path seen earlier on the same chain is a cycle; more than 10 nested
 *     include levels is an error; a missing or unreadable file is an error.
 * OpenClaw refuses to load a config with any of these errors, and so does
 * the launch (IncludeError → the config is "unreadable" → refused).
 *
 * Stricter than OpenClaw, on purpose: an OPENCLAW_INCLUDE_ROOTS entry that is
 * neither absolute nor `~`-relative is ignored (OpenClaw resolves it against
 * its own working directory and home-path rules), so an include that only
 * such an entry would admit is refused.
 *
 * Also stricter: a `__proto__` key anywhere (the main file or an included
 * one) is refused, where OpenClaw loads the config (see protoKeyPath).
 *
 * Checked against the real thing (2026-09-28, OpenClaw 2026.7.1 and
 * 2026.9.6, `openclaw config get` / `config validate`): the split config in
 * test/unit/openclaw-include.test.ts resolves to the same models; an include
 * outside the config directory, a hardlinked file, a cycle, a missing file
 * and a sibling key beside a non-object include are refused by both; a
 * symlink whose target stays inside is accepted by both.
 *
 * Environment substitution (`${VAR}`) runs AFTER includes in OpenClaw and is
 * not done here: an include path is taken literally by both, and a model
 * reference that still reads `${…}` names no provider the check accepts.
 */
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, normalize, relative, resolve } from "node:path";
import { parseJson5 } from "./json5.js";

export const INCLUDE_KEY = "$include";
/** OpenClaw's MAX_INCLUDE_FILE_BYTES. */
export const MAX_INCLUDE_FILE_BYTES = 2 * 1024 * 1024;
/** OpenClaw's MAX_INCLUDE_PATH_LENGTH. */
export const MAX_INCLUDE_PATH_LENGTH = 4096;
/** OpenClaw's include depth limit. */
export const MAX_INCLUDE_DEPTH = 10;

export class IncludeError extends Error {
  constructor(message: string, readonly includePath: string) {
    super(message);
    this.name = "IncludeError";
  }
}

/** The file operations the resolver needs (a seam for the unit tests). */
export interface IncludeFs {
  realpath(p: string): string;
  lstat(p: string): { isFile(): boolean; isSymbolicLink(): boolean; nlink: number; size: number };
  stat(p: string): { isFile(): boolean; nlink: number; size: number };
  readFile(p: string): string;
}

const nodeFs: IncludeFs = {
  realpath: (p) => realpathSync(p),
  lstat: (p) => lstatSync(p),
  stat: (p) => lstatSync(realpathSync(p)),
  readFile: (p) => readFileSync(p, "utf8"),
};

type Json = Record<string, unknown>;

const BLOCKED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function isPlainObject(v: unknown): v is Json {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** OpenClaw's include merge (deepMerge with arrays: "concat"). */
export function includeMerge(target: unknown, source: unknown): unknown {
  if (Array.isArray(target) && Array.isArray(source)) return [...target, ...source];
  if (isPlainObject(target) && isPlainObject(source)) {
    const out: Json = {};
    for (const [k, v] of Object.entries(target)) if (!BLOCKED_KEYS.has(k)) out[k] = v;
    for (const [k, v] of Object.entries(source)) {
      if (BLOCKED_KEYS.has(k)) continue;
      out[k] = Object.prototype.hasOwnProperty.call(out, k) ? includeMerge(out[k], v) : v;
    }
    return out;
  }
  return source;
}

/** `candidate` is `root` or below it. */
function isInside(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

interface Root { dir: string; realDir: string }

function safeRealpath(fs: IncludeFs, p: string): string {
  try { return normalize(fs.realpath(p)); } catch { return p; }
}

/** The OPENCLAW_INCLUDE_ROOTS entries this resolver can read (absolute or
 *  `~`-relative; the rest are ignored, see the module comment). */
export function includeRoots(env: Record<string, string | undefined>, home: string): string[] {
  const raw = env["OPENCLAW_INCLUDE_ROOTS"]?.trim();
  if (!raw) return [];
  const out: string[] = [];
  for (const entry of raw.split(":")) {
    const t = entry.trim();
    if (t === "") continue;
    let p: string | null = null;
    if (t === "~") p = home;
    else if (t.startsWith("~/")) p = join(home, t.slice(2));
    else if (isAbsolute(t)) p = t;
    if (p !== null && !out.includes(normalize(p))) out.push(normalize(p));
  }
  return out;
}

export interface ResolveIncludesOptions {
  env?: Record<string, string | undefined>;
  home?: string;
  fs?: IncludeFs;
}

/** The dotted path of the first `__proto__` key in `node`, or null. OpenClaw
 *  copies a config object key by key with plain assignment, and assigning
 *  `__proto__` sets the copy's PROTOTYPE rather than a key, so what OpenClaw
 *  would then read from that object is not what the launcher reads (json5.ts
 *  keeps the key as an own property). No real config needs one: refused. */
export function protoKeyPath(node: unknown, where = ""): string | null {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) { const p = protoKeyPath(node[i], `${where}[${i}]`); if (p) return p; }
    return null;
  }
  if (!isPlainObject(node)) return null;
  for (const [k, v] of Object.entries(node)) {
    const at = where ? `${where}.${k}` : k;
    if (k === "__proto__") return at;
    const p = protoKeyPath(v, at);
    if (p) return p;
  }
  return null;
}

/** True when `node` holds a `$include` key anywhere. */
export function hasInclude(node: unknown): boolean {
  if (Array.isArray(node)) return node.some(hasInclude);
  if (!isPlainObject(node)) return false;
  return Object.prototype.hasOwnProperty.call(node, INCLUDE_KEY) || Object.values(node).some(hasInclude);
}

/**
 * Resolve every `$include` in `doc`, the parsed config at `configPath`.
 * Returns a doc with none left. Throws IncludeError on anything OpenClaw
 * would refuse to load (and on the stricter cases in the module comment).
 */
export function resolveOpenclawIncludes(doc: unknown, configPath: string, opts: ResolveIncludesOptions = {}): unknown {
  const proto = protoKeyPath(doc);
  if (proto !== null) throw new IncludeError(`the config has a __proto__ key (${proto}), which OpenClaw would not read as written`, configPath);
  if (!hasInclude(doc)) return doc;
  const fs = opts.fs ?? nodeFs;
  const env = opts.env ?? process.env;
  const home = opts.home ?? env["HOME"] ?? homedir();
  const mainPath = normalize(resolve(configPath));
  const configDir = dirname(mainPath);
  const roots: Root[] = [configDir, ...includeRoots(env, home)].map((dir) => ({ dir, realDir: safeRealpath(fs, dir) }));

  const containing = (candidate: string, field: keyof Root): Root | null =>
    roots.find((r) => isInside(r[field], candidate)) ?? null;

  const loadFile = (includePath: string, basePath: string, visited: ReadonlySet<string>, depth: number): unknown => {
    if (includePath.includes("\0")) throw new IncludeError("the include path contains a null byte", includePath);
    if (includePath.length >= MAX_INCLUDE_PATH_LENGTH) throw new IncludeError("the include path is too long", includePath);
    const resolved = normalize(isAbsolute(includePath) ? includePath : resolve(dirname(basePath), includePath));
    if (resolved.length >= MAX_INCLUDE_PATH_LENGTH) throw new IncludeError("the resolved include path is too long", includePath);
    if (containing(resolved, "dir") === null) {
      throw new IncludeError(`it is outside the config directory ${configDir} (and outside OPENCLAW_INCLUDE_ROOTS)`, includePath);
    }
    // OpenClaw's order: a missing file passes the path checks and fails at
    // the read, after the cycle and depth checks.
    let missing = false;
    try {
      const real = normalize(fs.realpath(resolved));
      if (containing(real, "realDir") === null) {
        throw new IncludeError(`it resolves through a symlink to ${real}, outside the config directory`, includePath);
      }
    } catch (e) {
      if (e instanceof IncludeError) throw e;
      const code = (e as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") throw new IncludeError(`the file cannot be resolved (${code ?? String(e)})`, includePath);
      missing = true;
    }
    if (visited.has(resolved)) throw new IncludeError(`circular include: ${[...visited, resolved].join(" -> ")}`, includePath);
    if (depth >= MAX_INCLUDE_DEPTH) throw new IncludeError(`more than ${MAX_INCLUDE_DEPTH} nested include levels`, includePath);
    if (missing) throw new IncludeError("the file does not exist", includePath);
    let raw: string;
    try {
      const st = fs.stat(resolved);
      if (!st.isFile()) throw new IncludeError("it is not a regular file", includePath);
      if (st.nlink > 1) throw new IncludeError("it has more than one hard link, which OpenClaw refuses", includePath);
      if (st.size > MAX_INCLUDE_FILE_BYTES) throw new IncludeError(`it is larger than ${MAX_INCLUDE_FILE_BYTES} bytes`, includePath);
      raw = fs.readFile(resolved);
    } catch (e) {
      if (e instanceof IncludeError) throw e;
      throw new IncludeError(`the file cannot be read (${(e as NodeJS.ErrnoException).code ?? String(e)})`, includePath);
    }
    let parsed: unknown;
    try { parsed = parseJson5(raw); } catch (e) {
      throw new IncludeError(`the file is not JSON5 (${e instanceof Error ? e.message : String(e)})`, includePath);
    }
    const proto = protoKeyPath(parsed);
    if (proto !== null) throw new IncludeError(`the file has a __proto__ key (${proto}), which OpenClaw would not read as written`, includePath);
    return processNode(parsed, resolved, new Set([...visited, resolved]), depth + 1);
  };

  const processNode = (node: unknown, basePath: string, visited: ReadonlySet<string>, depth: number): unknown => {
    if (Array.isArray(node)) return node.map((n) => processNode(n, basePath, visited, depth));
    if (!isPlainObject(node)) return node;
    if (!Object.prototype.hasOwnProperty.call(node, INCLUDE_KEY)) {
      const out: Json = {};
      for (const [k, v] of Object.entries(node)) {
        Object.defineProperty(out, k, { value: processNode(v, basePath, visited, depth), enumerable: true, writable: true, configurable: true });
      }
      return out;
    }
    const value = node[INCLUDE_KEY];
    let included: unknown;
    if (typeof value === "string") included = loadFile(value, basePath, visited, depth);
    else if (Array.isArray(value)) {
      included = {};
      for (const item of value) {
        if (typeof item !== "string") throw new IncludeError(`a $include list item is a ${typeof item}, not a path`, String(item));
        included = includeMerge(included, loadFile(item, basePath, visited, depth));
      }
    } else {
      throw new IncludeError(`$include is a ${value === null ? "null" : typeof value}, not a path or a list of paths`, String(value));
    }
    const others = Object.keys(node).filter((k) => k !== INCLUDE_KEY);
    if (others.length === 0) return included;
    if (!isPlainObject(included)) {
      throw new IncludeError("keys beside $include need the included content to be an object", typeof value === "string" ? value : INCLUDE_KEY);
    }
    const rest: Json = {};
    for (const k of others) {
      Object.defineProperty(rest, k, { value: processNode(node[k], basePath, visited, depth), enumerable: true, writable: true, configurable: true });
    }
    return includeMerge(included, rest);
  };

  return processNode(doc, mainPath, new Set([mainPath]), 0);
}
