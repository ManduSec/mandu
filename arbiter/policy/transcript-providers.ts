/**
 * transcript-providers — which model provider a past session's requests
 * went to, for the story `mandu scan` tells (plan 17 §3 item 4,
 * docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md).
 *
 * The story says "it left this computer in Claude Code's next request to
 * Anthropic". That is only true where Claude Code talked to Anthropic: an
 * agent's own settings can point it elsewhere (Claude Code on Bedrock,
 * Vertex or Foundry, an `ANTHROPIC_BASE_URL` to a gateway; Codex with
 * another `model_provider` or base URL). This module reads those settings
 * the way each agent keeps them and answers only a kind, `anthropic`,
 * `openai` or `other`; the report says "the model provider" for `other`.
 *
 *   - Claude Code: the `env` block of its settings files, the user's
 *     `settings.json` (under `CLAUDE_CONFIG_DIR` when set), the managed
 *     settings (`/etc/claude-code/managed-settings.json`, macOS's
 *     `/Library/Application Support/ClaudeCode/managed-settings.json`) and
 *     a project's `.claude/settings.json` and `.claude/settings.local.json`
 *     in the session's directory; and the environment itself.
 *     `CLAUDE_CODE_USE_BEDROCK`, `_VERTEX` or `_FOUNDRY` on, or an
 *     `ANTHROPIC_BASE_URL` outside `anthropic.com`, makes it `other`.
 *   - Codex: `config.toml` (under `CODEX_HOME` when set), its
 *     `model_provider` (that of the active `profile` when one is set) and
 *     that provider's `model_providers.<id>.base_url`, its
 *     `openai_base_url` (the built-in provider's); and the environment's
 *     `OPENAI_BASE_URL`. A provider other than `openai` is `other` unless
 *     its base URL is OpenAI's. And a project's `.codex/config.toml`
 *     layers, read for a session the way Codex reads them for its working
 *     directory: one in each directory from the project root (the nearest
 *     directory up from it holding a `project_root_markers` entry, `.git`
 *     by default; none found, the directory itself) down to it, each only
 *     when the user's `projects."<dir>".trust_level` is `trusted` for that
 *     directory (else for the root), the closer one winning. Codex 0.162
 *     ignores the provider keys there (`model_provider`, `model_providers`,
 *     `profile`, `profiles`, `openai_base_url`: "Ignored unsupported
 *     project-local config keys"), an older Codex may not have, and a
 *     session may have run on one: so a trusted project's layers that turn
 *     the user's setting away from OpenAI count, the cautious way (another
 *     provider for a record that names none, a base URL off OpenAI's for
 *     any), and never make it OpenAI.
 *
 * What a session's own record names still wins where it names a provider
 * (Codex's `model_provider`, OpenCode's `providerID`, …): a session that
 * ran on OpenAI before the config moved to another provider went to
 * OpenAI. A record that names the agent's own provider is still `other`
 * when the settings send that provider's requests somewhere else: Claude
 * Code's record names a model (`claude-*`), not where it was served, and
 * Codex's `openai` follows `OPENAI_BASE_URL`. Today's settings, not the
 * session's: a hint, read the cautious way, so when unsure the answer is
 * `other`.
 *
 * Read-only, and nothing read leaves here but the kind: no URL, host,
 * provider id or setting is in an answer. A file that is not a regular
 * file, is over {@link SETTINGS_MAX_BYTES} or does not parse gives
 * nothing.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { lstatSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { TOML_PAIR_RE, TOML_TABLE_RE, tomlKeyParts, tomlString } from "./mcp-config.js";
import type { ModelProvider, TranscriptAgent } from "./transcript-scan.js";

/** A settings file over this is not read. */
export const SETTINGS_MAX_BYTES = 1024 * 1024;

/** What an agent's settings say about where its requests go. */
export interface ProviderSetting {
  /** Who a session whose record names no provider went to (Codex's
   *  `model_provider`). */
  pick?: ModelProvider;
  /** The settings send the agent's own provider's requests elsewhere: a
   *  record naming the agent's own provider then says `other`. */
  elsewhere?: true;
}

export type ProviderSettings = Partial<Record<TranscriptAgent, ProviderSetting>>;

/** Each agent's own provider: the one its record names by default. */
const OWN: Partial<Record<TranscriptAgent, ModelProvider>> = { "claude-code": "anthropic", codex: "openai" };

/**
 * The provider a session's requests went to: what the record names, else
 * what the settings pick, else the agent's own; `other` when the settings
 * send the agent's own provider elsewhere. Pure.
 */
export function resolveProvider(agent: TranscriptAgent, record: ModelProvider | undefined, ...settings: Array<ProviderSetting | undefined>): ModelProvider {
  const own = OWN[agent] ?? "other";
  const pick = settings.find((s) => s?.pick !== undefined)?.pick;
  const p = record ?? pick ?? own;
  return p === own && p !== "other" && settings.some((s) => s?.elsewhere) ? "other" : p;
}

/** Two settings as one: the first's pick over the second's, either's
 *  elsewhere. Pure. */
export function mergeSetting(a: ProviderSetting | undefined, b: ProviderSetting | undefined): ProviderSetting | undefined {
  const pick = a?.pick ?? b?.pick;
  const out: ProviderSetting = { ...(pick !== undefined ? { pick } : {}), ...(a?.elsewhere || b?.elsewhere ? { elsewhere: true as const } : {}) };
  return out.pick === undefined && out.elsewhere === undefined ? undefined : out;
}

/** Is this URL's host outside `domain`? An unreadable URL is (cautious). */
function outside(url: string | undefined, domain: string): boolean {
  if (url === undefined || url.trim() === "") return false;
  try {
    const h = new URL(url.trim()).hostname.toLowerCase();
    return h !== domain && !h.endsWith(`.${domain}`);
  } catch {
    return true;
  }
}

/** A flag the agent reads as on: anything but empty, `0`, `false`, `no` or
 *  `off` (cautious: a value the agent might read as on is on). */
const on = (v: string | undefined): boolean => v !== undefined && !/^(?:|0|false|no|off)$/i.test(v.trim());

/** Claude Code's settings in an environment (the process's, or a settings
 *  file's `env` block). Pure. */
export function claudeCodeSetting(env: Readonly<Record<string, string | undefined>>): ProviderSetting | undefined {
  const elsewhere = on(env["CLAUDE_CODE_USE_BEDROCK"]) || on(env["CLAUDE_CODE_USE_VERTEX"]) || on(env["CLAUDE_CODE_USE_FOUNDRY"]) || outside(env["ANTHROPIC_BASE_URL"], "anthropic.com");
  return elsewhere ? { elsewhere: true } : undefined;
}

/** A settings file's `env` block as strings (a number or a boolean as its
 *  text, as Claude Code reads them). Null when the text is not a JSON
 *  object. Pure. */
export function settingsEnv(text: string): Record<string, string> | null {
  let o: unknown;
  try { o = JSON.parse(text); } catch { return null; }
  if (typeof o !== "object" || o === null || Array.isArray(o)) return null;
  const env = (o as Record<string, unknown>)["env"];
  const out: Record<string, string> = {};
  if (typeof env !== "object" || env === null || Array.isArray(env)) return out;
  for (const [k, v] of Object.entries(env as Record<string, unknown>)) {
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") out[k] = String(v);
  }
  return out;
}

/** Every one-line string value of a TOML text, by its whole key path
 *  (`model_providers.azure.base_url`). An array table's pairs are left
 *  out. Pure. */
export function tomlStrings(content: string): Map<string, string> {
  const out = new Map<string, string>();
  let table: string[] | null = [];
  for (const raw of content.split("\n")) {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (/^\s*(?:#.*)?$/.test(line)) continue;
    if (/^\s*\[\[/.test(line)) { table = null; continue; }
    const t = TOML_TABLE_RE.exec(line);
    if (t) { table = tomlKeyParts(t[1]!); continue; }
    if (table === null) continue;
    const pair = TOML_PAIR_RE.exec(line);
    if (!pair) continue;
    const s = tomlString(pair[4]!.trim(), 0);
    if (s === null || !/^\s*(?:#.*)?$/.test(s.rest)) continue;
    const value = pair[4]!.trim()[0] === '"' ? s.raw.replace(/\\(["\\])/g, "$1") : s.raw;
    out.set([...table, ...tomlKeyParts(pair[2]!)].join("."), value);
  }
  return out;
}

/** Codex's settings in a config's string values, with the environment. Pure. */
function codexSettingOf(cfg: ReadonlyMap<string, string>, env: Readonly<Record<string, string | undefined>>): ProviderSetting | undefined {
  const profile = cfg.get("profile");
  const id = (profile !== undefined ? cfg.get(`profiles.${profile}.model_provider`) : undefined) ?? cfg.get("model_provider") ?? "openai";
  const base = cfg.get(`model_providers.${id}.base_url`);
  const out: ProviderSetting = {};
  if (id !== "openai") out.pick = base !== undefined && !outside(base, "openai.com") ? "openai" : "other";
  // The built-in provider follows OPENAI_BASE_URL and `openai_base_url`; a
  // table of its own name (Codex refuses one) is read too, the cautious way.
  if (outside(env["OPENAI_BASE_URL"], "openai.com") || outside(cfg.get("openai_base_url"), "openai.com") || outside(cfg.get("model_providers.openai.base_url"), "openai.com")) out.elsewhere = true;
  return out.pick === undefined && out.elsewhere === undefined ? undefined : out;
}

/** Codex's settings: its `config.toml` text (when read) and the
 *  environment. Pure. */
export function codexSetting(configToml: string | null, env: Readonly<Record<string, string | undefined>>): ProviderSetting | undefined {
  return codexSettingOf(configToml === null ? new Map<string, string>() : tomlStrings(configToml), env);
}

/**
 * What a project's trusted Codex config layers (root first) add to the
 * user's setting, laid over the user's `config.toml` (each later layer over
 * the earlier, so the closer one wins): `pick: "other"` when they pick a
 * provider off OpenAI the user's does not (it counts for a session whose
 * record names none: a record names the provider its session used), and
 * `elsewhere` when they send the built-in provider's requests elsewhere
 * (`openai_base_url`, which a record naming `openai` would not show). Only
 * away from OpenAI, never back to it: Codex 0.162 ignores these keys in a
 * project's config, so they cannot have made a session OpenAI's. Pure.
 */
export function codexProjectSetting(userToml: string | null, layers: readonly string[]): ProviderSetting | undefined {
  const user = userToml === null ? new Map<string, string>() : tomlStrings(userToml);
  const merged = new Map(user);
  for (const text of layers) for (const [k, v] of tomlStrings(text)) merged.set(k, v);
  const before = codexSettingOf(user, {});
  const after = codexSettingOf(merged, {});
  const out: ProviderSetting = {};
  if (after?.pick === "other" && before?.pick !== "other") out.pick = "other";
  if (after?.elsewhere && !before?.elsewhere) out.elsewhere = true;
  return out.pick === undefined && out.elsewhere === undefined ? undefined : out;
}

/** Codex's project root markers in the user's config: `project_root_markers`
 *  as a one-line array of names (`[]`: none, so the root is the session's
 *  directory), else `.git`, Codex's default. Pure. */
export function codexRootMarkers(userToml: string | null): string[] {
  const m = /^\s*project_root_markers\s*=\s*\[([^\]\n]*)\]\s*(?:#.*)?$/m.exec(userToml ?? "");
  if (m === null) return [".git"];
  const names = m[1]!.split(",").map((x) => x.trim()).filter((x) => x !== "").map((x) => /^"([^"\\/]+)"$|^'([^'/]+)'$/.exec(x));
  return names.every((x) => x !== null) ? names.map((x) => x![1] ?? x![2]!) : [".git"];
}

/** The user's trust in each project directory (`projects."<dir>".trust_level`). Pure. */
export function codexTrust(userToml: string | null): Map<string, string> {
  const out = new Map<string, string>();
  for (const [k, v] of userToml === null ? [] : tomlStrings(userToml)) {
    if (k.startsWith("projects.") && k.endsWith(".trust_level")) out.set(k.slice("projects.".length, -".trust_level".length), v);
  }
  return out;
}

/**
 * The directories whose `.codex/config.toml` Codex reads for a session in
 * `cwd`, root first: from the project root (the nearest directory up from
 * `cwd` holding one of `markers`; none found, `cwd` itself) down to `cwd`,
 * each whose trust (its own entry, else the root's) is `trusted`. Pure but
 * for `exists`.
 */
export function codexProjectDirs(cwd: string, markers: readonly string[], trust: ReadonlyMap<string, string>, exists: (p: string) => boolean): string[] {
  const chain: string[] = [];
  let root: string | undefined;
  for (let d = cwd, i = 0; i < 128; i++) {
    chain.push(d);
    if (markers.some((m) => exists(join(d, m)))) { root = d; break; }
    const up = dirname(d);
    if (up === d) break;
    d = up;
  }
  const dirs = root === undefined ? [cwd] : chain.reverse();
  const top = dirs[0]!;
  return dirs.filter((d) => (trust.get(d) ?? trust.get(top)) === "trusted");
}

/** Is anything at this path (a marker: a directory, a file, a link)? */
function existsAt(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

/** A small regular file's text, or null. */
function readSmall(path: string): string | null {
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > SETTINGS_MAX_BYTES) return null;
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

/** Claude Code's settings in the `env` blocks of these files, merged. */
function claudeCodeFiles(paths: readonly string[], read: (p: string) => string | null): ProviderSetting | undefined {
  let out: ProviderSetting | undefined;
  for (const p of paths) {
    const text = read(p);
    const env = text === null ? null : settingsEnv(text);
    if (env !== null) out = mergeSetting(out, claudeCodeSetting(env));
  }
  return out;
}

/** The managed settings files Claude Code reads on this computer. */
export const CLAUDE_MANAGED_SETTINGS = ["/etc/claude-code/managed-settings.json", "/Library/Application Support/ClaudeCode/managed-settings.json"];

/**
 * The settings of `home`'s agents: Claude Code's user (and, with `system`,
 * managed) settings files and Codex's `config.toml`, with `env` (the
 * agents' directory variables and their provider variables; pass `{}` for
 * another home than this process's, as `transcriptSources` does). Reads
 * files; answers kinds only.
 */
export function providerSettingsOf(opts: { home: string; env: Readonly<Record<string, string | undefined>>; system?: boolean; read?: (p: string) => string | null }): ProviderSettings {
  const read = opts.read ?? readSmall;
  const env = opts.env;
  const claudeDir = env["CLAUDE_CONFIG_DIR"] || join(opts.home, ".claude");
  const out: ProviderSettings = {};
  const cc = mergeSetting(claudeCodeSetting(env), claudeCodeFiles([join(claudeDir, "settings.json"), ...(opts.system ? CLAUDE_MANAGED_SETTINGS : [])], read));
  if (cc !== undefined) out["claude-code"] = cc;
  const cx = codexSetting(read(join(codexDirOf(opts.home, env), "config.toml")), env);
  if (cx !== undefined) out.codex = cx;
  return out;
}

/** Codex's own directory for `home`: `CODEX_HOME` when set. */
export function codexDirOf(home: string, env: Readonly<Record<string, string | undefined>>): string {
  return env["CODEX_HOME"] || join(home, ".codex");
}

/**
 * A project's own settings, for a session that ran in `cwd`: Claude Code's
 * `.claude/settings.json` and `.claude/settings.local.json` there; for
 * Codex, given `codexDir` (its user config's directory, {@link codexDirOf}),
 * the trusted `.codex/config.toml` layers from the project root down to
 * `cwd` ({@link codexProjectDirs}, {@link codexProjectSetting}). Each
 * directory is answered once. Reads files; answers kinds only.
 */
export function projectProviderReader(opts: { read?: (p: string) => string | null; exists?: (p: string) => boolean; codexDir?: string } = {}): (agent: TranscriptAgent, cwd: string | undefined) => ProviderSetting | undefined {
  const read = opts.read ?? readSmall;
  const exists = opts.exists ?? existsAt;
  const seen = new Map<string, ProviderSetting | undefined>();
  let user: { text: string | null; markers: string[]; trust: Map<string, string> } | undefined;
  const codexOf = (cwd: string): ProviderSetting | undefined => {
    if (opts.codexDir === undefined) return undefined;
    if (user === undefined) {
      const text = read(join(opts.codexDir, "config.toml"));
      user = { text, markers: codexRootMarkers(text), trust: codexTrust(text) };
    }
    // No trusted project, no layer Codex reads: none is looked for.
    if (![...user.trust.values()].includes("trusted")) return undefined;
    const layers: string[] = [];
    for (const d of codexProjectDirs(cwd, user.markers, user.trust, exists)) {
      const dir = join(d, ".codex");
      if (dir === opts.codexDir) continue; // the user's own config, not a project's
      const text = read(join(dir, "config.toml"));
      if (text !== null) layers.push(text);
    }
    return layers.length === 0 ? undefined : codexProjectSetting(user.text, layers);
  };
  return (agent, cwd) => {
    if ((agent !== "claude-code" && agent !== "codex") || cwd === undefined || !cwd.startsWith("/")) return undefined;
    const key = `${agent}\u0000${cwd}`;
    if (!seen.has(key)) {
      if (seen.size >= 4096) return undefined;
      seen.set(key, agent === "codex" ? codexOf(cwd) : claudeCodeFiles([join(cwd, ".claude", "settings.json"), join(cwd, ".claude", "settings.local.json")], read));
    }
    return seen.get(key);
  };
}
