/**
 * opencode-global-code — the user's OWN OpenCode code extensions under Mandu
 * (supported-agents.md §2.3 item 12). Mandu-new (no reference origin).
 *
 * WHAT. Item 11 (opencode-project-code.ts) keeps a repository's plugins and
 * custom tools out of a session with confidentiality ON. The user's own ones
 * run the same way, inside OpenCode's process, writing the model request
 * itself past every check: the modules in the global config directory's
 * `plugin`, `plugins`, `tool` and `tools` (`$XDG_CONFIG_HOME/opencode`, or
 * `$OPENCODE_CONFIG_DIR`, and `~/.opencode`), and the packages a global
 * config document names under `plugin` / `plugins` (npm plugins such as
 * oh-my-opencode, which OpenCode installs into its cache and imports).
 * Measured with a project plugin (item 11): the plugin copied a pinned
 * reader's raw output and another agent's credential store into the system
 * prompt; on 2.x a plugin also runs inside the server process, which the
 * holder taint exempts, so it could send held bytes out on 443. A global
 * plugin is the same code in another folder, and an injected agent that
 * could write one (before write-protection held those folders) planted it
 * for every later session.
 *
 * THE RULE (maintainer decision 2026-10-07, "Off + Approvals"). With
 * confidentiality ON the user's own plugins and custom tools do not run
 * either, and the launch names them in plain words:
 *   - OpenCode 2: the launcher builds OpenCode's configuration itself (the
 *     config lockdown, agent-config.ts), so it leaves the global code
 *     directories out of the directory it links and drops `plugin` /
 *     `plugins` from the user's documents it merges (global, `OPENCODE_CONFIG`,
 *     `~/.opencode`, the inline `OPENCODE_CONFIG_CONTENT`).
 *   - OpenCode 1 reads its global directory itself, but it has a switch for
 *     exactly this: `OPENCODE_PURE=1` ("run without external plugins", the
 *     `--pure` flag) skips every plugin that is not built in, whatever named
 *     it (a plugin file, a global, project or inline `plugin` list, a TUI
 *     plugin), and keeps OpenCode's built-in auth plugins. Measured on
 *     1.18.13 (tests/sandbox/guard/opencode-project-plugins.test.ts). So a
 *     1.x launch with neither opt-in gets `OPENCODE_PURE=1`, and a project's
 *     plugins are left out the same way (item 11's refusal now covers only
 *     what the switch does not: custom tools). `--pure` does not skip custom
 *     tools (`{tool,tools}/*.{js,ts}` of every config directory), so a 1.x
 *     launch whose own directories hold one is REFUSED, naming the files.
 *
 * THE OPT-IN. MANDU_OPENCODE_GLOBAL_PLUGINS=1 (also `true`, `yes`, `on`)
 * runs the user's own, with a warning. On OpenCode 1 the switch is all or
 * nothing, so the project opt-in alone (MANDU_OPENCODE_PROJECT_PLUGINS=1)
 * cannot run a project's plugins while leaving the user's out: such a launch
 * is refused when the user has plugins, naming them. Mode `off` keeps
 * nothing from the model; the rule does not apply there.
 *
 * WRITES. The global config documents that can name a plugin
 * (`opencodeSettingFiles`) join the write-protect list (`ask`, label "an
 * OpenCode setting", write-protect.ts), beside the code directories item 11
 * put there: an agent cannot add a plugin for the next session without the
 * human's answer. OpenCode 1 adds a `$schema` key to each config document it
 * loads that lacks one; the launcher makes that edit itself before the launch
 * (`addOpencodeSchema`), so the hold does not stop OpenCode's own start.
 *
 * Pure but for the file reads (an injectable fs) and addOpencodeSchema.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { parseJson5 } from "./services/json5.js";
import {
  everyUserOpencodeDir, isModule, namesPlugins, OPENCODE_CODE_DIRS, OPENCODE_PROJECT_PLUGINS_ENV,
  realCodeFs, type CodeFs, type ProjectCodeFinding,
} from "./opencode-project-code.js";

/** The opt-in variable. */
export const OPENCODE_GLOBAL_PLUGINS_ENV = "MANDU_OPENCODE_GLOBAL_PLUGINS";

/** OpenCode 1's "no external plugins" switch (`--pure`). */
export const OPENCODE_PURE_ENV = "OPENCODE_PURE";

/** The opt-in is set: the user's own code extensions run. */
export function opencodeGlobalCodeAllowed(env: Record<string, string | undefined>): boolean {
  return /^(1|true|yes|on)$/i.test((env[OPENCODE_GLOBAL_PLUGINS_ENV] ?? "").trim());
}

type Env = Record<string, string | undefined>;

function xdgDir(env: Env, home: string): string {
  return resolve(join(env["XDG_CONFIG_HOME"] || join(home, ".config"), "opencode"));
}

/**
 * The user's own directories a generation reads code from: OpenCode 1 the
 * XDG global directory, `$OPENCODE_CONFIG_DIR` when set (an extra one there)
 * and `~/.opencode`; OpenCode 2 `$OPENCODE_CONFIG_DIR`, else the XDG one,
 * and `~/.opencode` (the user's values: the launcher points OpenCode 2's own
 * at its directory and links these in).
 */
export function globalOpencodeDirs(generation: 1 | 2, env: Env, home: string = env["HOME"] || homedir()): string[] {
  const dot = join(home, ".opencode");
  if (generation === 2) return [...new Set([env["OPENCODE_CONFIG_DIR"] ? resolve(env["OPENCODE_CONFIG_DIR"]) : xdgDir(env, home), dot])];
  return [...new Set([xdgDir(env, home), ...(env["OPENCODE_CONFIG_DIR"] ? [resolve(env["OPENCODE_CONFIG_DIR"])] : []), dot])];
}

/** The config document names of a user directory that can name plugins:
 *  OpenCode's `opencode.json(c)`, 1.x's legacy global `config.json` and its
 *  `tui.json(c)` (whose plugins run in its TUI). */
const DOC_NAMES_V1 = ["config.json", "opencode.json", "opencode.jsonc", "tui.json", "tui.jsonc"] as const;
const DOC_NAMES_V2 = ["opencode.json", "opencode.jsonc"] as const;

/** The user's config documents a generation reads that can name plugins:
 *  those of globalOpencodeDirs, and the files the user's env names
 *  (`OPENCODE_CONFIG`, 1.x's `OPENCODE_TUI_CONFIG`). */
export function globalOpencodeConfigDocs(generation: 1 | 2, env: Env, home: string = env["HOME"] || homedir()): string[] {
  const names = generation === 1 ? DOC_NAMES_V1 : DOC_NAMES_V2;
  const out = globalOpencodeDirs(generation, env, home).flatMap((d) => names.map((n) => join(d, n)));
  if (env["OPENCODE_CONFIG"]) out.push(resolve(env["OPENCODE_CONFIG"]));
  if (generation === 1 && env["OPENCODE_TUI_CONFIG"]) out.push(resolve(env["OPENCODE_TUI_CONFIG"]));
  return [...new Set(out)];
}

/** The inline layer's name in a finding. */
export const INLINE_CONFIG = "OPENCODE_CONFIG_CONTENT";

/**
 * Every code extension of the user's own a generation would load: the
 * modules in globalOpencodeDirs' `plugin`, `plugins`, `tool` and `tools`,
 * each config document of globalOpencodeConfigDocs that names a plugin (one
 * that does not parse counts), and the inline `OPENCODE_CONFIG_CONTENT` when
 * it names one.
 */
export function findOpencodeGlobalCode(
  generation: 1 | 2,
  env: Env,
  home: string = env["HOME"] || homedir(),
  fs: CodeFs = realCodeFs,
): ProjectCodeFinding[] {
  const out: ProjectCodeFinding[] = [];
  const seen = new Set<string>();
  const add = (f: ProjectCodeFinding): void => {
    const key = f.path === INLINE_CONFIG ? f.path : fs.real(f.path);
    if (seen.has(key)) return;
    seen.add(key);
    out.push(f);
  };
  for (const dir of globalOpencodeDirs(generation, env, home)) {
    if (!fs.isDir(dir)) continue;
    for (const sub of OPENCODE_CODE_DIRS) {
      const d = join(dir, sub);
      if (!fs.isDir(d)) continue;
      for (const name of fs.list(d)) {
        const full = join(d, name);
        if (isModule(name, full, generation, fs)) add({ path: full, kind: sub.startsWith("plugin") ? "plugin" : "tool" });
      }
    }
  }
  for (const doc of globalOpencodeConfigDocs(generation, env, home)) {
    if (!fs.isFile(doc)) continue;
    const text = fs.read(doc);
    if (text !== null && namesPlugins(text)) add({ path: doc, kind: "config" });
  }
  const inline = env[INLINE_CONFIG];
  if (inline !== undefined && inline.trim() !== "" && namesPlugins(inline)) add({ path: INLINE_CONFIG, kind: "config" });
  return out;
}

function describe(f: ProjectCodeFinding): string {
  return f.kind === "config" ? `${f.path} (names a plugin)` : f.path;
}

const WHY = "they would run inside OpenCode, where what they put into a model request is not checked";

/** The launch line (without `mandu: `) when the user's own plugins and
 *  custom tools are left out. */
export function opencodeGlobalCodeNotice(findings: readonly ProjectCodeFinding[]): string {
  return (
    `OpenCode — your own OpenCode plugins and custom tools are left out of this session (${WHY}): ` +
    `${findings.map(describe).join(", ")}. ${OPENCODE_GLOBAL_PLUGINS_ENV}=1 runs them unchecked.`
  );
}

/** The warning (without `mandu: `) of a launch whose opt-in runs them. */
export function opencodeGlobalCodeOptInWarning(findings: readonly ProjectCodeFinding[]): string {
  return (
    `WARNING: ${OPENCODE_GLOBAL_PLUGINS_ENV}=1 — your own OpenCode plugins and custom tools run inside the agent, ` +
    `and what they put into a model request is not checked: ${findings.map(describe).join(", ")}.`
  );
}

/** OpenCode 1 launch line when its switch leaves a project's plugins out. */
export function opencodeV1ProjectPluginsNotice(findings: readonly ProjectCodeFinding[]): string {
  return (
    `OpenCode — this project's plugins are left out (${WHY}): ` +
    `${findings.map(describe).join(", ")}. ${OPENCODE_PROJECT_PLUGINS_ENV}=1 runs them unchecked.`
  );
}

/** The refusal of an OpenCode 1 launch whose own directories hold a custom
 *  tool (`OPENCODE_PURE` does not skip tools). */
export function opencodeGlobalToolsRefusal(mode: string, tools: readonly ProjectCodeFinding[]): string {
  return (
    `refusing OpenCode in mode ${mode}: your OpenCode folders hold a custom tool, and ${WHY}: ` +
    `${tools.map(describe).join(", ")}. OpenCode 1 loads custom tools itself, so Mandu cannot leave them out. ` +
    `Move them out of the folder, use OpenCode 2 (Mandu leaves them out there), ` +
    `or set ${OPENCODE_GLOBAL_PLUGINS_ENV}=1 to run them unchecked.`
  );
}

/** The refusal of an OpenCode 1 launch with the project opt-in alone while
 *  the user has plugins of their own: OpenCode 1's switch is all or none. */
export function opencodeV1PluginSplitRefusal(mode: string, own: readonly ProjectCodeFinding[]): string {
  return (
    `refusing OpenCode in mode ${mode}: ${OPENCODE_PROJECT_PLUGINS_ENV}=1 asks to run this project's plugins, ` +
    `but OpenCode 1 can only run every plugin or none, and yours would run too (${WHY}): ${own.map(describe).join(", ")}. ` +
    `Set ${OPENCODE_GLOBAL_PLUGINS_ENV}=1 as well to run both unchecked, or unset ${OPENCODE_PROJECT_PLUGINS_ENV}.`
  );
}

/** What a launch with confidentiality ON does about OpenCode code. */
export interface OpencodeCodeDecision {
  /** A refusal message, or null. */
  refusal: string | null;
  /** Warning lines (without `mandu: `) for the opt-ins. */
  warnings: string[];
}

/**
 * The launch-time decision (run.ts) for OpenCode code with confidentiality
 * ON, both origins, both generations. The leaving-out itself happens where
 * the configuration is written (agent-config.ts), which prints the notices.
 *   OpenCode 2: never a refusal; each opt-in prints its warning.
 *   OpenCode 1, the switch on (neither opt-in): custom tools refuse (the
 *     user's first); plugins are left out.
 *   OpenCode 1, the global opt-in alone: a project's code refuses (item 11).
 *   OpenCode 1, the project opt-in alone: the user's custom tools refuse;
 *     the user's plugins refuse (the switch would drop the project's too).
 */
export function opencodeCodeDecision(i: {
  generation: 1 | 2;
  mode: string;
  project: readonly ProjectCodeFinding[];
  global: readonly ProjectCodeFinding[];
  projectAllowed: boolean;
  globalAllowed: boolean;
  projectRefusal: (mode: string, findings: readonly ProjectCodeFinding[]) => string;
}): OpencodeCodeDecision {
  const warnings: string[] = [];
  if (i.globalAllowed && i.global.length > 0) warnings.push(opencodeGlobalCodeOptInWarning(i.global));
  if (i.generation === 2) return { refusal: null, warnings };
  const tools = (fs: readonly ProjectCodeFinding[]): ProjectCodeFinding[] => fs.filter((f) => f.kind === "tool");
  const plugins = (fs: readonly ProjectCodeFinding[]): ProjectCodeFinding[] => fs.filter((f) => f.kind !== "tool");
  if (!i.globalAllowed && tools(i.global).length > 0) return { refusal: opencodeGlobalToolsRefusal(i.mode, tools(i.global)), warnings };
  if (!i.projectAllowed) {
    // With the switch on (no global opt-in) a project's plugins are left out
    // and only its tools refuse; with the global opt-in nothing is left out.
    const refused = i.globalAllowed ? [...i.project] : tools(i.project);
    if (refused.length > 0) return { refusal: i.projectRefusal(i.mode, refused), warnings };
    return { refusal: null, warnings };
  }
  if (!i.globalAllowed && plugins(i.global).length > 0) return { refusal: opencodeV1PluginSplitRefusal(i.mode, plugins(i.global)), warnings };
  return { refusal: null, warnings };
}

/** OpenCode 1 gets `OPENCODE_PURE=1` exactly when no plugin may run:
 *  confidentiality ON (or unknown) and neither opt-in. */
export function opencodeV1Pure(projectCode: boolean, globalCode: boolean): boolean {
  return !projectCode && !globalCode;
}

/**
 * The user's OpenCode settings files that can name a plugin, for the
 * write-protect list (`ask`, label "an OpenCode setting"): each config
 * document name of either generation in every user directory
 * (everyUserOpencodeDir), and the user's `OPENCODE_CONFIG` file.
 */
export function opencodeSettingFiles(env: Env): string[] {
  const home = env["HOME"];
  if (!home) return [];
  const out = everyUserOpencodeDir(env, home).flatMap((d) => DOC_NAMES_V1.map((n) => join(d, n)));
  if (env["OPENCODE_CONFIG"] && env["OPENCODE_CONFIG"].startsWith("/")) out.push(env["OPENCODE_CONFIG"]);
  return [...new Set(out)];
}

/** OpenCode 1's own `$schema` edit, as it makes it (the first `{` gets the
 *  key), or null when the text needs none: it does not parse as an object,
 *  or already has the key. */
export function withOpencodeSchema(text: string): string | null {
  let doc: unknown;
  try { doc = parseJson5(text); } catch { return null; }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) return null;
  if ((doc as Record<string, unknown>)["$schema"]) return null;
  if (!/^\s*\{/.test(text)) return null;
  return text.replace(/^\s*\{/, `{\n  "$schema": "https://opencode.ai/config.json",`);
}

/**
 * Before an OpenCode 1 launch: make OpenCode 1's own `$schema` edit to the
 * user's config documents it loads (the global directory's `config.json`,
 * `opencode.json`, `opencode.jsonc`, and those of `$OPENCODE_CONFIG_DIR` and
 * `~/.opencode`), which are on the write-protect list: OpenCode 1 would
 * otherwise make it at its start, and the guard would hold its start on the
 * human's answer. Mandu's own launcher runs outside the guard. Best-effort:
 * a file it cannot read or write is left for OpenCode (whose own write
 * failure is ignored). Returns the files changed.
 */
export function addOpencodeSchema(env: Env, home: string = env["HOME"] || homedir()): string[] {
  const changed: string[] = [];
  for (const d of globalOpencodeDirs(1, env, home)) {
    for (const n of ["config.json", "opencode.json", "opencode.jsonc"]) {
      const p = join(d, n);
      let text: string;
      try { text = readFileSync(p, "utf8"); } catch { continue; }
      const next = withOpencodeSchema(text);
      if (next === null) continue;
      try { writeFileSync(p, next); changed.push(p); } catch { /* left for OpenCode */ }
    }
  }
  return changed;
}
