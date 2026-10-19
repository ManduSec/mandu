/**
 * opencode-project-code — a project's OpenCode code extensions under Mandu
 * (supported-agents.md §2.3 item 11). Mandu-new (no reference origin).
 *
 * WHAT. OpenCode runs JavaScript and TypeScript modules INSIDE its own
 * process: plugins (`.opencode/plugin/*.ts`, `.opencode/plugins/`, and
 * packages a config document names under `plugin` / `plugins`) and, on
 * OpenCode 1, custom tools (`.opencode/tool/*.ts`, `.opencode/tools/`). A
 * plugin's hooks edit the model request itself: the system prompt
 * (`experimental.chat.system.transform` on 1.x, the session `context` hook
 * on 2.x), a tool's output after it ran (`tool.execute.after`, `execute.after`),
 * the request's endpoint and headers (2.x `model.request`, `http.request`).
 *
 * WHY IT IS NOT THE AGENT'S SHELL (measured 2026-10-06, OpenCode 1.18.13 and
 * 2.0.23 under the real launcher in mode `secrets`, the guard on, a scripted
 * model): a project plugin loaded on both; its own read of a labelled file
 * got the placeholder (the twin, as every program of the tree does), and its
 * connect to a loopback listener was refused (the guard). But the agent
 * process holds what the proxy masks only on the way out: the raw output of
 * a program on a file's `readers:` list (the tool_result is masked from the
 * call's tree; OpenCode itself saw the bytes) and OpenCode's own and other
 * agents' credential stores (never twinned, the runtime reads them).
 * The plugin copied both into the SYSTEM PROMPT, which no check reads, and
 * the scripted model received the registered secret and the store's key
 * raw. A custom tool's result carried a store file's key raw too: a tool no
 * spec maps is masked by what its input names and by the session's raw
 * reads, not whole. The proxy can check what OpenCode reports as a tool
 * result; it cannot check code that writes the request.
 *
 * THE RULE. A file the repository brings is text an injected agent (or the
 * repository's author) controls, so with confidentiality ON a project's code
 * extensions do not run:
 *   - OpenCode 2: the launcher builds OpenCode's configuration itself (the
 *     config lockdown, agent-config.ts buildOpencodeConfigDir and
 *     opencodeV2UserDoc), so it leaves the project's `plugin`, `plugins`,
 *     `tool` and `tools` directories out of the directory it links, and drops
 *     `plugin` / `plugins` from the project's config documents it merges.
 *     The launch says what it left out.
 *   - OpenCode 1 reads its project directories itself; Mandu cannot leave a
 *     part out without dropping the whole project configuration. Its own
 *     `OPENCODE_PURE=1` switch skips every plugin that is not built in
 *     (2026-10-07, opencode-global-code.ts), so the launcher sets it and a
 *     project's plugins are left out; a custom tool, which the switch does
 *     not skip, REFUSES the launch, naming each file and the way out
 *     (opencodeProjectCodeRefusal). With the user's own plugins opted in
 *     (MANDU_OPENCODE_GLOBAL_PLUGINS=1) the switch is off, and a project's
 *     plugins refuse as well.
 * The user's own ones (the global config directory, `~/.opencode`) are the
 * same code in another folder: opencode-global-code.ts (§2.3 item 12) leaves
 * them out too. write-protect.ts holds a change to them, and to the
 * project's directories, for the human's answer, so an injected agent cannot
 * plant one for the next session.
 *
 * THE OPT-OUT. MANDU_OPENCODE_PROJECT_PLUGINS=1 (also `true`, `yes`, `on`)
 * runs them as before, with a warning that what they put into a model
 * request is not checked. Mode `off` keeps nothing from the model, so the
 * rule does not apply there.
 *
 * Pure but for the file reads of findOpencodeProjectCode (an injectable fs).
 */
import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parseJson5 } from "./services/json5.js";

/** The opt-out variable. */
export const OPENCODE_PROJECT_PLUGINS_ENV = "MANDU_OPENCODE_PROJECT_PLUGINS";

/** The `.opencode` subdirectories whose modules OpenCode imports. */
export const OPENCODE_CODE_DIRS = ["plugin", "plugins", "tool", "tools"] as const;

/** The opt-out is set: the project's code extensions run. */
export function opencodeProjectCodeAllowed(env: Record<string, string | undefined>): boolean {
  return /^(1|true|yes|on)$/i.test((env[OPENCODE_PROJECT_PLUGINS_ENV] ?? "").trim());
}

/** One code extension a project carries. */
export interface ProjectCodeFinding {
  /** The file (or directory) OpenCode would load, or the config document. */
  path: string;
  kind: "plugin" | "tool" | "config";
}

export interface CodeFs {
  isDir: (p: string) => boolean;
  isFile: (p: string) => boolean;
  list: (p: string) => string[];
  read: (p: string) => string | null;
  real: (p: string) => string;
}

export const realCodeFs: CodeFs = {
  isDir: (p) => { try { return statSync(p).isDirectory(); } catch { return false; } },
  isFile: (p) => { try { return statSync(p).isFile(); } catch { return false; } },
  list: (p) => { try { return readdirSync(p).sort(); } catch { return []; } },
  read: (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } },
  real: (p) => { try { return realpathSync(p); } catch { return resolve(p); } },
};

/** A truthy OpenCode env flag, as OpenCode reads one (`1` or `true`). */
function ocFlag(v: string | undefined): boolean {
  return v !== undefined && /^(1|true)$/i.test(v.trim());
}

/** The user's own OpenCode directories: the global config directory
 *  (`$OPENCODE_CONFIG_DIR`, else `$XDG_CONFIG_HOME/opencode`) and
 *  `~/.opencode`, which OpenCode 1 reads for every project. */
export function userOpencodeDirs(env: Record<string, string | undefined>, home: string = env["HOME"] || homedir()): string[] {
  const global = env["OPENCODE_CONFIG_DIR"] || join(env["XDG_CONFIG_HOME"] || join(home, ".config"), "opencode");
  return [...new Set([resolve(global), join(home, ".opencode")])];
}

/** `start` and its ancestors, innermost first: up to the git repository
 *  root (the first with a `.git` entry) when `toRepoRoot`, else up to `/`. */
function ancestors(start: string, toRepoRoot: boolean, fs: CodeFs): string[] {
  const out: string[] = [];
  for (let d = resolve(start); ; d = dirname(d)) {
    out.push(d);
    if (toRepoRoot && (fs.isDir(join(d, ".git")) || fs.isFile(join(d, ".git")))) break;
    if (dirname(d) === d) break;
  }
  return out;
}

/**
 * The project directories OpenCode reads code and config from for a session
 * started in `starts`, innermost first, without the user's own
 * (userOpencodeDirs). OpenCode 1 walks from the start directory up to the
 * repository root (to `/` outside a repository) and reads none with its
 * OPENCODE_DISABLE_PROJECT_CONFIG; OpenCode 2 walks up to `/` (Mandu turns
 * its own project reading off and links these in itself, so the user's
 * switch does not apply there).
 */
export function opencodeProjectDirs(
  starts: readonly string[],
  generation: 1 | 2,
  env: Record<string, string | undefined>,
  home: string = env["HOME"] || homedir(),
  fs: CodeFs = realCodeFs,
): string[] {
  if (generation === 1 && ocFlag(env["OPENCODE_DISABLE_PROJECT_CONFIG"])) return [];
  const globalReal = fs.real(userOpencodeDirs(env, home)[0]!);
  const out: string[] = [];
  for (const s of starts) {
    // Started in the global config dir: OpenCode reads no project layer.
    if (fs.real(s) === globalReal) continue;
    for (const d of ancestors(s, generation === 1, fs)) if (!out.includes(d)) out.push(d);
  }
  // A directory's `.opencode` may be one of the user's own (`~/.opencode`):
  // projectDotDir leaves it out; the directory's own config documents
  // (`<dir>/opencode.json`) are still the project's.
  return out;
}

/** The `.opencode` directory of `dir`, unless it is one of the user's own. */
function projectDotDir(dir: string, env: Record<string, string | undefined>, home: string, fs: CodeFs): string | null {
  const dot = join(dir, ".opencode");
  const user = new Set(userOpencodeDirs(env, home).map((d) => fs.real(d)));
  return user.has(fs.real(dot)) ? null : dot;
}

/** Is `name` a module OpenCode loads from a code directory? OpenCode 1
 *  globs `*.{ts,js}`; OpenCode 2 also takes a directory (a package). */
export function isModule(name: string, full: string, generation: 1 | 2, fs: CodeFs): boolean {
  if (/\.(ts|js)$/.test(name) && (fs.isFile(full) || generation === 2)) return true;
  return generation === 2 && fs.isDir(full);
}

/** A config document's plugin list is non-empty (`plugin` on 1.x and in
 *  2.x's V1 spelling, `plugins` in 2.x's). A document that does not parse
 *  counts: OpenCode's reader may take what Mandu's does not. */
export function namesPlugins(text: string): boolean {
  let doc: unknown;
  try { doc = parseJson5(text); } catch { return true; }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) return true;
  for (const k of ["plugin", "plugins"]) {
    const v = (doc as Record<string, unknown>)[k];
    if (v === undefined || v === null) continue;
    if (Array.isArray(v) ? v.length > 0 : true) return true;
  }
  return false;
}

/** The config documents of a project directory that can name plugins:
 *  OpenCode's `opencode.json(c)` (and 1.x's `tui.json(c)`, whose plugins
 *  run in its TUI), beside the directory and in its `.opencode`. */
function configDocs(dir: string, dot: string | null, generation: 1 | 2): string[] {
  const names = generation === 1 ? ["opencode.json", "opencode.jsonc", "tui.json", "tui.jsonc"] : ["opencode.json", "opencode.jsonc"];
  return [...names.map((n) => join(dir, n)), ...(dot === null ? [] : names.map((n) => join(dot, n)))];
}

/**
 * Every code extension a project carries for a session started in `starts`
 * (the launch's cwd, and an `opencode <dir>` / `--dir <dir>` argument):
 * the modules in each project `.opencode`'s plugin and tool directories, and
 * each project config document that names plugins.
 */
export function findOpencodeProjectCode(
  starts: readonly string[],
  generation: 1 | 2,
  env: Record<string, string | undefined>,
  home: string = env["HOME"] || homedir(),
  fs: CodeFs = realCodeFs,
): ProjectCodeFinding[] {
  const out: ProjectCodeFinding[] = [];
  const seen = new Set<string>();
  const add = (f: ProjectCodeFinding): void => {
    const key = fs.real(f.path);
    if (seen.has(key)) return;
    seen.add(key);
    out.push(f);
  };
  const dirs = opencodeProjectDirs(starts, generation, env, home, fs);
  for (const dir of [...dirs].reverse()) {
    const dot = projectDotDir(dir, env, home, fs);
    if (dot !== null && fs.isDir(dot)) {
      for (const sub of OPENCODE_CODE_DIRS) {
        const d = join(dot, sub);
        if (!fs.isDir(d)) continue;
        for (const name of fs.list(d)) {
          const full = join(d, name);
          if (isModule(name, full, generation, fs)) add({ path: full, kind: sub.startsWith("plugin") ? "plugin" : "tool" });
        }
      }
    }
    for (const doc of configDocs(dir, dot, generation)) {
      if (!fs.isFile(doc)) continue;
      const text = fs.read(doc);
      if (text !== null && namesPlugins(text)) add({ path: doc, kind: "config" });
    }
  }
  return out;
}

/** The directories an `opencode` argv starts a session in, beside the cwd:
 *  the bare `opencode <dir>` form and `run --dir <dir>`. */
export function opencodeStartDirs(argv: readonly string[], cwd: string, fs: CodeFs = realCodeFs): string[] {
  const out = [resolve(cwd)];
  const first = argv[1];
  if (first !== undefined && !first.startsWith("-") && fs.isDir(resolve(cwd, first))) out.push(resolve(cwd, first));
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    const v = a === "--dir" ? argv[i + 1] : a.startsWith("--dir=") ? a.slice("--dir=".length) : undefined;
    if (v !== undefined && v !== "" && fs.isDir(resolve(cwd, v))) out.push(resolve(cwd, v));
  }
  return [...new Set(out)];
}

function describe(f: ProjectCodeFinding): string {
  return f.kind === "config" ? `${f.path} (names a plugin)` : f.path;
}

const WHY = "it would run inside OpenCode, where what it puts into a model request is not checked";

/** The refusal of an OpenCode 1 launch in a project that carries code
 *  extensions OpenCode 1's switch does not leave out (confidentiality ON, no
 *  opt-out): a custom tool, or any with the user's own opted in. */
export function opencodeProjectCodeRefusal(mode: string, findings: readonly ProjectCodeFinding[]): string {
  return (
    `refusing OpenCode in mode ${mode}: this project brings OpenCode code (a plugin or a custom tool), and ${WHY}: ` +
    `${findings.map(describe).join(", ")}. OpenCode 1 loads it from the project itself, so Mandu cannot leave it out. ` +
    `Remove it, use OpenCode 2 (Mandu leaves a project's plugins and tools out there), ` +
    `or set ${OPENCODE_PROJECT_PLUGINS_ENV}=1 to run it unchecked.`
  );
}

/** The launch line (without the `mandu: ` prefix) of an OpenCode 2 launch
 *  that left a project's code extensions out. */
export function opencodeProjectCodeNotice(findings: readonly ProjectCodeFinding[]): string {
  return (
    `OpenCode — this project's plugins and custom tools are left out (${WHY}): ` +
    `${findings.map(describe).join(", ")}. ${OPENCODE_PROJECT_PLUGINS_ENV}=1 runs them unchecked.`
  );
}

/** The warning (without the `mandu: ` prefix) of a launch whose opt-out
 *  runs them. */
export function opencodeProjectCodeOptOutWarning(findings: readonly ProjectCodeFinding[]): string {
  return (
    `WARNING: ${OPENCODE_PROJECT_PLUGINS_ENV}=1 — this project's OpenCode plugins and custom tools run inside ` +
    `the agent, and what they put into a model request is not checked: ${findings.map(describe).join(", ")}.`
  );
}

/** A project config document without its plugin list (`plugin`, `plugins`):
 *  what the launcher merges into OpenCode 2's run file. */
export function withoutPlugins<T extends Record<string, unknown>>(doc: T): { doc: T; dropped: boolean } {
  if (!("plugin" in doc) && !("plugins" in doc)) return { doc, dropped: false };
  const { plugin: _a, plugins: _b, ...rest } = doc as Record<string, unknown>;
  return { doc: rest as T, dropped: true };
}

/**
 * The OpenCode code directories a change to which waits for the human
 * (write-protect.ts, an `ask` entry each): files that run later, in the
 * user's next OpenCode session, under Mandu or not. This half: the user's
 * own (the global config directory and `~/.opencode`, which every session
 * loads), each `plugin`, `plugins`, `tool` and `tools`.
 */
export function userOpencodeCodeDirs(env: Record<string, string | undefined>): string[] {
  const home = env["HOME"];
  if (!home) return [];
  return codeDirsOf(everyUserOpencodeDir(env, home));
}

/** Every directory of the user's own that some OpenCode generation reads
 *  code and settings from: `$OPENCODE_CONFIG_DIR` when set (OpenCode 2's
 *  global directory then; an extra one on 1.x), the XDG one
 *  (`$XDG_CONFIG_HOME/opencode`, which OpenCode 1 reads whatever
 *  `$OPENCODE_CONFIG_DIR` says), and `~/.opencode`. */
export function everyUserOpencodeDir(env: Record<string, string | undefined>, home: string = env["HOME"] || homedir()): string[] {
  const xdg = join(env["XDG_CONFIG_HOME"] || join(home, ".config"), "opencode");
  const extra = env["OPENCODE_CONFIG_DIR"] ? [resolve(env["OPENCODE_CONFIG_DIR"])] : [];
  return [...new Set([...extra, resolve(xdg), join(home, ".opencode")])];
}

/** The project's half of the above: `cwd`'s chain up to the repository
 *  root (`cwd` alone outside one). */
export function projectOpencodeCodeDirs(cwd: string, fs: Pick<CodeFs, "isDir" | "isFile"> = realCodeFs): string[] {
  const chain = ancestors(cwd, true, { ...realCodeFs, ...fs });
  const inRepo = chain.some((d) => fs.isDir(join(d, ".git")) || fs.isFile(join(d, ".git")));
  return codeDirsOf((inRepo ? chain : [resolve(cwd)]).map((d) => join(d, ".opencode")));
}

function codeDirsOf(dots: readonly string[]): string[] {
  const out: string[] = [];
  for (const dot of dots) for (const sub of OPENCODE_CODE_DIRS) {
    const p = join(dot, sub);
    if (!out.includes(p)) out.push(p);
  }
  return out;
}
