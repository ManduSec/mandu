/**
 * mcp-config — the MCP and editor config files of the default secret
 * catalog (2026-10-21, docs/design/confidentiality/secret-discovery.md
 * §2.10): which files they are, which agent reads each in its own process,
 * and where in each the servers' values sit (with byte offsets on the
 * file's own text, so the twin can mask them in place).
 *
 * ── WHY ─────────────────────────────────────────────────────────────────────
 *
 * Every MCP user keeps tokens in these files: a GitHub token in a stdio
 * server's `env`, a Linear bearer in an HTTP server's `headers`, a
 * database URL in `args`. A model that reads the file ("fix my MCP setup")
 * sent them to its provider, since no catalog rule named the file (the
 * content tier left agents' and editors' own configs out, because a twin
 * the agent reads breaks every server it spawns from it). The decision of
 * 2026-10-21: catalog them, with the values kept where each server needs
 * them. This module is the pure half: the files, and the server entries in
 * them. The rules that mask a value are secret-extract.ts's (`mcpSpans`);
 * the walk's pass is secret-discovery.ts's; the launch posture (the
 * agent's own configs left readable to it) is the launcher's.
 *
 * ── THE FILES (`mcpConfigKind`, by name) ────────────────────────────────────
 *
 *   claude          `.claude.json` (Claude Code's user and local scopes:
 *                   top-level `mcpServers`, `projects[<dir>].mcpServers`)
 *   claude-project  `.mcp.json` (Claude Code's project scope; Cursor and
 *                   others read the same shape)
 *   cursor          `.cursor/mcp.json` (HOME or a project)
 *   vscode          `.vscode/mcp.json` (`servers`), VS Code's user
 *                   `Code/User/mcp.json`
 *   claude-desktop  `Claude/claude_desktop_config.json`
 *   windsurf        `.codeium/windsurf/mcp_config.json`
 *   codex           `.codex/config.toml` (`[mcp_servers.<name>]`); a
 *                   `config.toml` a `CODEX_HOME` moved is read as one by
 *                   its content (`mcpConfigKindOf`: a `[mcp_servers.…]`
 *                   table) and visited at `$CODEX_HOME/config.toml`
 *
 * Since 2026-10-22 (secret-discovery.md §2.10, "The other agents' and
 * tools' configs"):
 *
 *   opencode        `opencode.json` / `opencode.jsonc` (a project's, and
 *                   the global `~/.config/opencode/`, with its older
 *                   `config.json`): the `mcp` map, `environment`,
 *                   `headers`; `{env:VAR}` and `{file:path}` are references
 *   goose           `.config/goose/config.yaml`: the `extensions` map,
 *                   `envs` (alias `env`), `headers`, `uri`; `env_keys`
 *                   names keys of Goose's secret store (keyring or
 *                   `secrets.yaml`), so no value is read from it
 *   gemini          `.gemini/settings.json` (user and project):
 *                   `mcpServers`, `env`, `headers`, `url` / `httpUrl`;
 *                   `$VAR` and `${VAR}` are references
 *   zed             `.config/zed/settings.json`, a project's
 *                   `.zed/settings.json`: `context_servers`, `env` (beside
 *                   `command`, or the older `command.env`), an extension
 *                   server's `settings`, `url`, `headers`
 *   continue        `.continue/config.yaml` / `config.json` and the
 *                   `.continue/mcpServers/*.yaml|*.json` blocks: the
 *                   `mcpServers` list (YAML) or map (JSON), `env`, `with`,
 *                   `requestOptions.headers`, `url`; the deprecated
 *                   `config.json`'s `experimental.modelContextProtocolServers`
 *                   (`transport.env`); `${{ secrets.X }}` is a reference
 *
 * ── THE ENTRIES ─────────────────────────────────────────────────────────────
 *
 * JSON: a positional parser (JSONC comments and trailing commas accepted, as
 * VS Code writes them) finds each server object under `mcpServers`,
 * `servers`, `mcp.servers` and (claude) `projects.*.mcpServers`, and in it
 * the string values of `env`, `headers`, `url` / `serverUrl` / `httpUrl`
 * and `type`. A file that does not parse gives no entry (the generic JSON
 * reading still masks its secret-named keys). TOML (Codex): a line reader
 * of `[mcp_servers.<name>]` tables, their `env` / `http_headers` /
 * `env_http_headers` sub-tables, and single-line inline tables of those
 * names (`env = { K = "v" }`), each value with its offsets; an inline table
 * it cannot read in full (multi-line, nested) makes the whole reading null,
 * and the extractor then twins the file whole (its fail-safe). YAML (Goose,
 * Continue): a positional reader of the block subset those tools write
 * (`yamlServerEntries`), over the server section only; an anchor, an alias,
 * a tag, a multi-line plain or flow value in it, or a block scalar where a
 * value is read, makes the reading null (the extractor then twins the file
 * whole, and the content decision falls back to the file's words).
 *
 * Every walk here is linear in the text and bounded in depth.
 *
 * Mandu-new (no reference origin).
 */

import { looksLikeSecretValue } from "./secret-detectors.js";
import type { Agent, ScanOnlyAgent } from "../src/generated/agents.js";

/** The supported agents that read an MCP config in their own process: every
 *  agent of the registry (its generated copy) but OpenClaw, which keeps no
 *  MCP config of its own (it runs Claude Code's and Codex's logins). */
export type McpConfigReader = Exclude<Agent, "openclaw">;

/** The MCP config files Mandu knows, by what reads them: each reader's own
 *  (named by its agent), Claude Code's project `.mcp.json`, the editors'
 *  and apps', and two tools the past-sessions scan knows (Cursor, Gemini
 *  CLI) whose configs no supported agent reads. */
export type McpConfigKind =
  | McpConfigReader | "claude-project" | "vscode" | "claude-desktop" | "windsurf" | "zed" | "continue"
  | Extract<ScanOnlyAgent, "cursor" | "gemini">;

/**
 * Which MCP config `path` is, by its name alone (no file is read), or null.
 * A name only: `.mcp.json`, `.claude.json` and `opencode.json(c)` anywhere,
 * the others by their directory. A Codex config a `CODEX_HOME` moved out of
 * `.codex` is known by its content (`mcpConfigKindOf`). Pure.
 */
export function mcpConfigKind(path: string): McpConfigKind | null {
  const parts = path.split("/");
  const base = parts[parts.length - 1] ?? "";
  const parent = parts[parts.length - 2] ?? "";
  const grand = parts[parts.length - 3] ?? "";
  if (base === ".claude.json") return "claude";
  if (base === ".mcp.json") return "claude-project";
  if (base === "mcp.json" && parent === ".cursor") return "cursor";
  if (base === "mcp.json" && (parent === ".vscode" || (parent === "User" && /^(?:Code|Code - Insiders|VSCodium|Cursor)$/.test(grand)))) return "vscode";
  if (base === "claude_desktop_config.json" && parent === "Claude") return "claude-desktop";
  if (base === "mcp_config.json" && parent === "windsurf" && grand === ".codeium") return "windsurf";
  if (base === "config.toml" && parent === ".codex") return "codex";
  if (base === "opencode.json" || base === "opencode.jsonc") return "opencode";
  if (base === "config.json" && parent === "opencode" && grand === ".config") return "opencode";
  if (base === "config.yaml" && parent === "goose" && grand === ".config") return "goose";
  if (base === "settings.json" && parent === ".gemini") return "gemini";
  if (base === "settings.json" && (parent === ".zed" || (parent === "zed" && grand === ".config"))) return "zed";
  if ((base === "config.yaml" || base === "config.json") && parent === ".continue") return "continue";
  if (/\.(?:ya?ml|json)$/.test(base) && parent === "mcpServers" && grand === ".continue") return "continue";
  return null;
}

/** A `[mcp_servers.<name>]` table header (Codex's MCP servers). */
const CODEX_MCP_TABLE_RE = /^[ \t]*\[[ \t]*(?:mcp_servers|"mcp_servers")[ \t]*\./m;

/**
 * `mcpConfigKind`, and a `config.toml` by its content: one that holds a
 * `[mcp_servers.…]` table is Codex's (the file a `CODEX_HOME` moved out of
 * `.codex`, which no name tells; no other tool writes such a table into a
 * `config.toml`). Reading it as Codex's masks more of it, never less (the
 * generic TOML reading plus the server values). Pure.
 */
export function mcpConfigKindOf(path: string, content: string): McpConfigKind | null {
  const k = mcpConfigKind(path);
  if (k !== null) return k;
  return path.endsWith("/config.toml") || path === "config.toml" ? (CODEX_MCP_TABLE_RE.test(content) ? "codex" : null) : null;
}

/** May `path` be an MCP config (`mcpConfigKind`, or any `config.toml`, which
 *  `mcpConfigKindOf` judges by its content)? For a caller that holds no
 *  text, before it re-reads one. Pure. */
export function mcpConfigLike(path: string): boolean {
  return mcpConfigKind(path) !== null || path.endsWith("/config.toml");
}

/** The supported agent that reads a config of `kind` in its OWN process to
 *  start its MCP servers (Claude Code: `.claude.json`, `.mcp.json`; Codex:
 *  `config.toml`; OpenCode: `opencode.json`; Goose: `config.yaml`), or null
 *  for an editor's, an app's or another tool's config that no supported
 *  agent reads (Gemini CLI, Zed and Continue are none of Mandu's agents).
 *  Pure. */
export function mcpConfigReader(kind: McpConfigKind): McpConfigReader | null {
  if (kind === "claude" || kind === "claude-project") return "claude";
  if (kind === "codex") return "codex";
  if (kind === "opencode") return "opencode";
  if (kind === "goose") return "goose";
  return null;
}

/** A reference token a client expands before use: `${VAR}` (Claude Code,
 *  Cursor, VS Code's `${input:…}` and `${env:…}`, Gemini CLI), Continue's
 *  `${{ secrets.X }}`, OpenCode's `{env:VAR}` and `{file:path}`. */
const REF_TOKEN_RE = /\$\{\{[^{}]*\}\}|\$\{[^{}]*\}|\{(?:env|file):[^{}]*\}/g;
/** A whole value that is one reference: a token above, or Gemini CLI's bare
 *  `$VAR` (upper-case, as environment names are written), optionally after
 *  an auth scheme word (`Bearer $TOKEN`). */
const WHOLE_REF_RE = /^(?:(?:bearer|basic|token)\s+)?(?:\$\{\{[^{}]*\}\}|\$\{[^{}]*\}|\{(?:env|file):[^{}]*\}|\$[A-Z_][A-Z0-9_]*)$/i;

/** Is `raw` exactly one reference (`mcpReference`'s whole form): what a
 *  generic key rule may have taken for a secret-named key's value
 *  (`"GITHUB_TOKEN": "${GITHUB_TOKEN}"`). The bare `$VAR` form only in
 *  upper case. Pure. */
export function mcpWholeReference(raw: string): boolean {
  const v = raw.trim();
  if (!WHOLE_REF_RE.test(v)) return false;
  // `$VAR` bare: upper case only (WHOLE_REF_RE is case-blind for the scheme).
  const bare = /\$([A-Za-z_][A-Za-z0-9_]*)$/.exec(v);
  return bare === null || v.endsWith("}") || bare[1] === bare[1]!.toUpperCase();
}

/**
 * Is `raw` a value the client expands from somewhere else, not a secret
 * itself: a whole reference (`mcpWholeReference`), or text holding a
 * reference token (`Bearer ${TOKEN}`, `{env:KEY}`, `${{ secrets.X }}`)
 * whose rest has no word that reads as a credential (a token written
 * beside a reference is still a token). Pure.
 */
export function mcpReference(raw: string): boolean {
  if (mcpWholeReference(raw)) return true;
  REF_TOKEN_RE.lastIndex = 0;
  if (!REF_TOKEN_RE.test(raw)) return false;
  const rest = raw.replace(REF_TOKEN_RE, " ");
  return !rest.split(/[\s"'{}:,=\\]+/).some((w) => looksLikeSecretValue(w));
}

/**
 * The MCP config files a launch HOME holds at their default places (and the
 * places `CLAUDE_CONFIG_DIR` and `CODEX_HOME` move Claude Code's and Codex's
 * to: only absolute values count). The walk visits each directly, wherever
 * a prune would have kept it out (`~/.codex` is an agent store, `~/Library`
 * a pruned macOS folder). Since 2026-10-22 also OpenCode's, Goose's,
 * Gemini CLI's, Zed's and Continue's per-user files at their default
 * places (an `XDG_CONFIG_HOME`, `GOOSE_PATH_ROOT` or `OPENCODE_CONFIG`
 * that moves one is not followed: secret-discovery.md §2.10). Pure.
 */
export function mcpHomeConfigPaths(home: string, env: Readonly<Record<string, string | undefined>> = {}): string[] {
  const h = home.replace(/\/+$/, "");
  const out = [
    `${h}/.claude.json`,
    `${h}/.mcp.json`,
    `${h}/.cursor/mcp.json`,
    `${h}/.config/Claude/claude_desktop_config.json`,
    `${h}/Library/Application Support/Claude/claude_desktop_config.json`,
    `${h}/.codeium/windsurf/mcp_config.json`,
    `${h}/.config/Code/User/mcp.json`,
    `${h}/Library/Application Support/Code/User/mcp.json`,
    `${h}/.codex/config.toml`,
    `${h}/.config/opencode/opencode.json`,
    `${h}/.config/opencode/opencode.jsonc`,
    `${h}/.config/opencode/config.json`,
    `${h}/.config/goose/config.yaml`,
    `${h}/.gemini/settings.json`,
    `${h}/.config/zed/settings.json`,
    `${h}/.continue/config.yaml`,
    `${h}/.continue/config.json`,
  ];
  const abs = (v: string | undefined): string | null => (typeof v === "string" && v.startsWith("/") ? v.replace(/\/+$/, "") : null);
  const claudeDir = abs(env["CLAUDE_CONFIG_DIR"]);
  if (claudeDir !== null) out.push(`${claudeDir}/.claude.json`);
  const codexHome = abs(env["CODEX_HOME"]);
  if (codexHome !== null) out.push(`${codexHome}/config.toml`);
  return [...new Set(out)];
}

/** Where a value sits in a server entry. */
export type McpValueRole = "env" | "header" | "url" | "bearer";

/** One string value of a server entry, on the file's own text. */
export interface McpValue {
  role: McpValueRole;
  /** The variable's or the header's name (`GITHUB_TOKEN`, `Authorization`);
   *  the key itself for `url` and `bearer` (`url`, `bearer_token`). */
  name: string;
  /** Offsets of the value's text between its quotes, end-exclusive. */
  start: number;
  end: number;
  /** The text as written (escapes kept, as the extractor's values are). */
  raw: string;
  /** The value's dotted path in the file (YAML: `extensions.github.envs.X`,
   *  the field name the twin gives it, as the YAML key rules name theirs);
   *  absent for JSON and TOML, which name a value by `name`. */
  field?: string;
}

/** One configured MCP server. */
export interface McpServerEntry {
  name: string;
  /** Offsets of the whole entry (the object, or the TOML tables). */
  start: number;
  end: number;
  /** `http` when the entry names a URL or a remote transport, else `stdio`. */
  transport: "stdio" | "http";
  /** The server's URL as written (an HTTP or SSE server), else null. */
  url: string | null;
  values: McpValue[];
}

/** The entries of `content`, read as the config `path` names, or null when
 *  `path` is no MCP config or the content cannot be read in full. Pure. */
export function mcpServerEntries(path: string, content: string): McpServerEntry[] | null {
  const kind = mcpConfigKindOf(path, content);
  if (kind === null) return null;
  if (kind === "codex") return tomlServerEntries(content);
  if (/\.ya?ml$/i.test(path)) return kind === "goose" || kind === "continue" ? yamlServerEntries(content, kind) : null;
  return jsonServerEntries(content, kind);
}

/** The host (`host[:port]`, lower case) of an `http(s)://` URL, or null.
 *  A URL with a `${…}` the client expands names no host. Pure. */
export function mcpUrlHost(url: string): { host: string; https: boolean } | null {
  if (url.includes("${") || !/^https?:\/\//i.test(url)) return null;
  try {
    const u = new URL(url);
    if (u.hostname === "") return null;
    return { host: u.host.toLowerCase(), https: u.protocol === "https:" };
  } catch {
    return null;
  }
}

// ── JSON, with positions ────────────────────────────────────────────────────

type JNode =
  | { t: "obj"; start: number; end: number; entries: Array<{ key: string; value: JNode }> }
  | { t: "arr"; start: number; end: number; items: JNode[] }
  | { t: "str"; start: number; end: number; raw: string }
  | { t: "lit"; start: number; end: number };

/** How deep a JSON config nests at most before the reading gives up. */
const MAX_JSON_DEPTH = 64;

/** A JSON (JSONC: comments, trailing commas) text with each node's offsets,
 *  or null when it does not parse. A string's `start`/`end` are inside its
 *  quotes. Iterative over whitespace and strings, recursive over nesting
 *  (bounded by MAX_JSON_DEPTH). Pure. */
export function parseJsonPositions(text: string): JNode | null {
  let i = 0;
  const n = text.length;
  const ws = (): boolean => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09 || c === 0xfeff) { i++; continue; }
      if (c === 0x2f && text[i + 1] === "/") { const nl = text.indexOf("\n", i); i = nl < 0 ? n : nl + 1; continue; }
      if (c === 0x2f && text[i + 1] === "*") { const close = text.indexOf("*/", i + 2); if (close < 0) return false; i = close + 2; continue; }
      break;
    }
    return true;
  };
  const str = (): { t: "str"; start: number; end: number; raw: string } | null => {
    if (text[i] !== '"') return null;
    const start = i + 1;
    let j = start;
    for (; j < n; j++) {
      const c = text[j];
      if (c === "\\") { j++; continue; }
      if (c === '"') break;
      if (c === "\n") return null;
    }
    if (j >= n) return null;
    i = j + 1;
    return { t: "str", start, end: j, raw: text.slice(start, j) };
  };
  const value = (depth: number): JNode | null => {
    if (depth > MAX_JSON_DEPTH || !ws() || i >= n) return null;
    const c = text[i];
    if (c === '"') return str();
    if (c === "{") {
      const start = i++;
      const entries: Array<{ key: string; value: JNode }> = [];
      for (;;) {
        if (!ws()) return null;
        if (text[i] === "}") { i++; return { t: "obj", start, end: i, entries }; }
        const k = str();
        if (k === null || !ws() || text[i] !== ":") return null;
        i++;
        const v = value(depth + 1);
        if (v === null) return null;
        entries.push({ key: k.raw, value: v });
        if (!ws()) return null;
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; return { t: "obj", start, end: i, entries }; }
        return null;
      }
    }
    if (c === "[") {
      const start = i++;
      const items: JNode[] = [];
      for (;;) {
        if (!ws()) return null;
        if (text[i] === "]") { i++; return { t: "arr", start, end: i, items }; }
        const v = value(depth + 1);
        if (v === null) return null;
        items.push(v);
        if (!ws()) return null;
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; return { t: "arr", start, end: i, items }; }
        return null;
      }
    }
    const m = /^(?:true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i, i + 64));
    if (m === null) return null;
    const start = i;
    i += m[0].length;
    return { t: "lit", start, end: i };
  };
  const root = value(0);
  if (root === null || !ws() || i !== n) return null;
  return root;
}

function field(o: JNode | undefined, key: string): JNode | undefined {
  if (o?.t !== "obj") return undefined;
  let found: JNode | undefined;
  for (const e of o.entries) if (e.key === key) found = e.value; // the last one wins, as JSON.parse
  return found;
}

/** The server entries of a JSON MCP config, each `[name, object]`: every
 *  `{name: entry}` map, and (Continue) every object of a server list. */
function jsonServerNodes(root: JNode, kind: McpConfigKind): Array<[string, JNode]> {
  const out: Array<[string, JNode]> = [];
  const add = (m: JNode | undefined): void => {
    if (m?.t === "obj") for (const e of m.entries) out.push([e.key, e.value]);
    else if (m?.t === "arr" && kind === "continue") {
      m.items.forEach((it, i) => {
        const n = field(it, "name");
        out.push([n?.t === "str" ? n.raw : `#${i}`, it]);
      });
    }
  };
  add(field(root, "mcpServers"));
  add(field(root, "servers"));
  add(field(field(root, "mcp"), "servers"));
  if (kind === "claude") {
    const projects = field(root, "projects");
    if (projects?.t === "obj") for (const p of projects.entries) add(field(p.value, "mcpServers"));
  }
  // OpenCode: `mcp: {<name>: {type, command, environment, url, headers}}`
  // (opencode.ai/docs/mcp-servers). A `servers` key there is VS Code's
  // settings form, read above; OpenCode names no server `servers`.
  if (kind === "opencode") {
    const mcp = field(root, "mcp");
    if (mcp?.t === "obj") for (const e of mcp.entries) if (e.key !== "servers") out.push([e.key, e.value]);
  }
  // Zed: `context_servers: {<name>: {command, args, env} | {url, headers}}`
  // (zed.dev/docs/ai/mcp).
  if (kind === "zed") add(field(root, "context_servers"));
  // Continue's deprecated config.json: `experimental.modelContextProtocolServers:
  // [{transport: {type, command, args, env, url}}]`.
  if (kind === "continue") {
    const legacy = field(field(root, "experimental"), "modelContextProtocolServers");
    if (legacy?.t === "arr") legacy.items.forEach((it, i) => out.push([`#${i}`, it]));
  }
  return out;
}

/** The string pairs of an object node. */
function stringPairs(o: JNode | undefined): Array<{ key: string; value: { start: number; end: number; raw: string } }> {
  if (o?.t !== "obj") return [];
  const out: Array<{ key: string; value: { start: number; end: number; raw: string } }> = [];
  for (const e of o.entries) if (e.value.t === "str") out.push({ key: e.key, value: e.value });
  return out;
}

const REMOTE_TYPE_RE = /^(?:http|https|sse|streamable-?http|streamablehttp|ws|websocket|remote)$/i;

function jsonServerEntries(content: string, kind: McpConfigKind): McpServerEntry[] | null {
  const root = parseJsonPositions(content);
  if (root === null || root.t !== "obj") return null;
  const out: McpServerEntry[] = [];
  for (const [name, node] of jsonServerNodes(root, kind)) {
    if (node.t !== "obj") continue;
    // Continue's deprecated form keeps the server in `transport`.
    const t = field(node, "transport");
    const entry = kind === "continue" && t?.t === "obj" ? t : node;
    const values: McpValue[] = [];
    const envMaps = [field(entry, "env")];
    // OpenCode's `environment`; Zed's older `command: {path, args, env}`
    // and an extension server's `settings` (its own keys, a token among
    // them); Continue's `with` (a hub block's inputs).
    if (kind === "opencode") envMaps.push(field(entry, "environment"));
    if (kind === "zed") envMaps.push(field(field(entry, "command"), "env"), field(entry, "settings"));
    if (kind === "continue") envMaps.push(field(entry, "with"));
    for (const m of envMaps) for (const p of stringPairs(m)) values.push({ role: "env", name: p.key, start: p.value.start, end: p.value.end, raw: p.value.raw });
    const headerMaps = [field(entry, "headers")];
    if (kind === "continue") headerMaps.push(field(field(entry, "requestOptions"), "headers"));
    for (const m of headerMaps) for (const p of stringPairs(m)) values.push({ role: "header", name: p.key, start: p.value.start, end: p.value.end, raw: p.value.raw });
    let url: string | null = null;
    for (const k of ["url", "serverUrl", "httpUrl"]) {
      const u = field(entry, k);
      if (u?.t === "str") {
        url = u.raw;
        values.push({ role: "url", name: k, start: u.start, end: u.end, raw: u.raw });
      }
    }
    const tf = field(entry, "type");
    const type = tf ?? (entry === node ? t : undefined);
    const remote = url !== null || (type?.t === "str" && REMOTE_TYPE_RE.test(type.raw));
    out.push({ name, start: node.start, end: node.end, transport: remote ? "http" : "stdio", url, values });
  }
  return out;
}

// ── YAML, with positions (Goose's config.yaml, Continue's) ──────────────────

type YNode =
  | { t: "map"; start: number; end: number; entries: Array<{ key: string; keyStart: number; value: YNode | null }> }
  | { t: "seq"; start: number; end: number; items: Array<YNode | null> }
  | { t: "str"; start: number; end: number; raw: string }
  /** A block scalar (`|`, `>`): skipped, its text never placed. */
  | { t: "block"; start: number; end: number };

/** A line of the section: its offset, indent and text after the indent. */
interface YLine { at: number; ind: number; body: string }

class YamlUnread extends Error {}

/** How deep a YAML section nests at most before the reading gives up. */
const MAX_YAML_DEPTH = 32;

/** A mapping key at the start of `s` and the text after its `:`, or null. */
function yamlKey(s: string): { key: string; rest: string; restAt: number } | null {
  const m = /^(?:"((?:[^"\\]|\\.)*)"|'((?:[^']|'')*)'|([^\s#'"{}[\],&*!|>%@`?:-][^#:]*?|-[^\s#:][^#:]*?))[ \t]*:(?=[ \t]|$)/.exec(s);
  if (m === null) return null;
  const key = m[1] !== undefined ? m[1].replace(/\\(.)/g, "$1") : m[2] !== undefined ? m[2].replace(/''/g, "'") : m[3]!.trimEnd();
  let restAt = m[0].length;
  while (restAt < s.length && (s[restAt] === " " || s[restAt] === "\t")) restAt++;
  return { key, rest: s.slice(restAt), restAt };
}

/** A scalar at the start of `s` (absolute offset `at`), alone on its line
 *  but for a comment: its text between the quotes (or the plain text). */
function yamlScalar(s: string, at: number): { t: "str"; start: number; end: number; raw: string } {
  const c = s[0];
  if (c === '"' || c === "'") {
    let j = 1;
    for (; j < s.length; j++) {
      if (c === '"' && s[j] === "\\") { j++; continue; }
      if (s[j] === c) {
        if (c === "'" && s[j + 1] === "'") { j++; continue; }
        break;
      }
    }
    if (j >= s.length || !/^[ \t]*(?:#.*)?$/.test(s.slice(j + 1))) throw new YamlUnread("an unclosed or trailed quoted scalar");
    return { t: "str", start: at + 1, end: at + j, raw: s.slice(1, j) };
  }
  if (c === "&" || c === "*" || c === "!" || c === "%" || c === "@" || c === "`") throw new YamlUnread("an anchor, alias, tag or reserved indicator");
  const hash = s.search(/[ \t]#/);
  const text = (hash < 0 ? s : s.slice(0, hash)).trimEnd();
  return { t: "str", start: at, end: at + text.length, raw: text };
}

/** A one-line flow collection at the start of `s` (`{}`, `[a, "b"]`,
 *  `{ K: v }`, nested ones up to MAX_YAML_DEPTH); one that does not close
 *  on its line, or holds an anchor, alias or tag, is not read. */
function yamlFlow(s: string, at: number): YNode {
  let i = 0;
  const skip = (): void => { while (i < s.length && (s[i] === " " || s[i] === "\t")) i++; };
  const scalar = (stops: string): { t: "str"; start: number; end: number; raw: string } => {
    skip();
    const c = s[i];
    if (c === '"' || c === "'") {
      let j = i + 1;
      for (; j < s.length; j++) {
        if (c === '"' && s[j] === "\\") { j++; continue; }
        if (s[j] === c) { if (c === "'" && s[j + 1] === "'") { j++; continue; } break; }
      }
      if (j >= s.length) throw new YamlUnread("an unclosed quoted flow scalar");
      const node = { t: "str" as const, start: at + i + 1, end: at + j, raw: s.slice(i + 1, j) };
      i = j + 1;
      return node;
    }
    if (c === "&" || c === "*" || c === "!") throw new YamlUnread("an anchor, alias or tag");
    let j = i;
    while (j < s.length && !stops.includes(s[j]!)) j++;
    const text = s.slice(i, j).trimEnd();
    const node = { t: "str" as const, start: at + i, end: at + i + text.length, raw: text };
    i = j;
    return node;
  };
  const value = (stops: string, depth: number): YNode => {
    skip();
    return s[i] === "{" || s[i] === "[" ? collection(depth + 1) : scalar(stops);
  };
  const collection = (depth: number): YNode => {
    if (depth > MAX_YAML_DEPTH) throw new YamlUnread("nested past the depth bound");
    const start = at + i;
    const open = s[i]!;
    const close = open === "{" ? "}" : "]";
    i++;
    const entries: Array<{ key: string; keyStart: number; value: YNode | null }> = [];
    const items: Array<YNode | null> = [];
    for (;;) {
      skip();
      if (s[i] === close) { i++; break; }
      if (i >= s.length) throw new YamlUnread("a flow collection that does not close on its line");
      if (open === "{") {
        const keyStart = at + i;
        const k = scalar(":,{}[]");
        skip();
        if (s[i] !== ":") throw new YamlUnread("a flow mapping entry with no value");
        i++;
        skip();
        const v = s[i] === "," || s[i] === "}" ? null : value(",{}[]", depth);
        entries.push({ key: k.raw, keyStart, value: v });
      } else {
        items.push(value(",{}[]", depth));
      }
      skip();
      if (s[i] === ",") { i++; continue; }
      if (s[i] === close) { i++; break; }
      throw new YamlUnread("a flow collection this reader cannot read");
    }
    return open === "{" ? { t: "map", start, end: at + i, entries } : { t: "seq", start, end: at + i, items };
  };
  const root = collection(0);
  if (!/^[ \t]*(?:#.*)?$/.test(s.slice(i))) throw new YamlUnread("text after a flow collection");
  return root;
}

/**
 * The block YAML of `lines` (blank and comment-only lines removed) as a
 * node tree with offsets: block mappings and sequences (a sequence item's
 * mapping on the dash's line included, and a sequence at its key's indent),
 * one-line scalars (plain, single- and double-quoted) and one-line flow
 * collections. A block scalar is skipped as a `block` node. Anything else
 * (an anchor, alias or tag, a multi-line plain scalar or flow collection, a
 * complex key, a tab in an indent) throws YamlUnread. Linear in the lines,
 * bounded in depth.
 */
function parseYamlBlock(lines: YLine[]): YNode | null {
  let i = 0;
  const lineEnd = (l: YLine): number => l.at + l.ind + l.body.length;
  /** The value after a key's or a dash's `:` / `-`, on the line `l`. */
  const inlineValue = (rest: string, restAt: number, ind: number, depth: number, fromKey: boolean): YNode | null => {
    if (rest === "" || rest.startsWith("#")) {
      const next = lines[i];
      if (next === undefined) return null;
      if (next.ind > ind) return node(next.ind, depth + 1);
      // A sequence at its key's own indent (`key:\n- a`).
      if (fromKey && next.ind === ind && (next.body === "-" || next.body.startsWith("- "))) return node(ind, depth + 1);
      return null;
    }
    if (/^[|>][0-9+-]*[ \t]*(?:#.*)?$/.test(rest)) {
      let end = restAt + rest.length;
      while (i < lines.length && lines[i]!.ind > ind) end = lineEnd(lines[i++]!);
      return { t: "block", start: restAt, end };
    }
    if (rest[0] === "{" || rest[0] === "[") return yamlFlow(rest, restAt);
    const s = yamlScalar(rest, restAt);
    if (i < lines.length && lines[i]!.ind > ind) throw new YamlUnread("a multi-line plain scalar");
    return s;
  };
  const node = (ind: number, depth: number): YNode | null => {
    if (depth > MAX_YAML_DEPTH) throw new YamlUnread("nested past the depth bound");
    const first = lines[i];
    if (first === undefined || first.ind !== ind) return null;
    if (first.body === "-" || first.body.startsWith("- ")) {
      const items: Array<YNode | null> = [];
      const start = first.at + first.ind;
      let end = start;
      while (i < lines.length && lines[i]!.ind === ind && (lines[i]!.body === "-" || lines[i]!.body.startsWith("- "))) {
        const l = lines[i]!;
        let off = 1;
        while (off < l.body.length && l.body[off] === " ") off++;
        const rest = l.body.slice(off);
        if (rest !== "" && !rest.startsWith("#") && yamlKey(rest) !== null) {
          // A mapping that starts on the dash's line: its first key there,
          // the rest at that key's column.
          lines[i] = { at: l.at, ind: l.ind + off, body: rest };
          items.push(node(l.ind + off, depth + 1));
        } else {
          i++;
          items.push(inlineValue(rest, l.at + l.ind + off, ind, depth, false));
        }
        end = i > 0 ? lineEnd(lines[i - 1]!) : end;
      }
      return { t: "seq", start, end, items };
    }
    const entries: Array<{ key: string; keyStart: number; value: YNode | null }> = [];
    const start = first.at + first.ind;
    let end = start;
    while (i < lines.length && lines[i]!.ind === ind) {
      const l = lines[i]!;
      const k = yamlKey(l.body);
      if (k === null) {
        if (l.body === "-" || l.body.startsWith("- ")) break; // handled by the caller (a key's same-indent sequence)
        throw new YamlUnread("a line that is no key");
      }
      i++;
      entries.push({ key: k.key, keyStart: l.at + l.ind, value: inlineValue(k.rest, l.at + l.ind + k.restAt, ind, depth, true) });
      end = lineEnd(lines[i - 1]!);
    }
    if (i < lines.length && lines[i]!.ind > ind) throw new YamlUnread("an indent this reader cannot place");
    return { t: "map", start, end, entries };
  };
  const root = node(lines[0]?.ind ?? 0, 0);
  if (i !== lines.length) throw new YamlUnread("text after the section");
  return root;
}

/** The lines of `content` from the top-level `key:` line through its
 *  block (every following line indented, or a top-level `- ` item), blank
 *  and comment-only lines left out; null when there is no such key. */
function yamlSection(content: string, key: string): YLine[] | null {
  const out: YLine[] = [];
  let at = 0;
  let inSection = false;
  for (const rawLine of content.split("\n")) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    const lineAt = at;
    at += rawLine.length + 1;
    const lead = /^[ \t]*/.exec(line)![0];
    const body = line.slice(lead.length);
    if (body === "" || body.startsWith("#")) continue;
    if (!inSection) {
      if (lead === "") {
        const k = yamlKey(body);
        if (k !== null && k.key === key) { inSection = true; out.push({ at: lineAt, ind: 0, body }); }
      }
      continue;
    }
    if (lead === "" && !(body === "-" || body.startsWith("- "))) break;
    if (lead.includes("\t")) throw new YamlUnread("a tab in an indent");
    out.push({ at: lineAt, ind: lead.length, body });
  }
  return inSection ? out : null;
}

function ymap(n: YNode | null | undefined, key: string): YNode | null | undefined {
  if (n?.t !== "map") return undefined;
  let found: YNode | null | undefined;
  for (const e of n.entries) if (e.key === key) found = e.value;
  return found;
}

/** The string values of a mapping node, with their keys; a block scalar
 *  among them cannot be placed, so the reading gives up (YamlUnread). */
function yamlStringPairs(n: YNode | null | undefined): Array<{ key: string; value: { start: number; end: number; raw: string } }> {
  if (n?.t !== "map") return [];
  const out: Array<{ key: string; value: { start: number; end: number; raw: string } }> = [];
  for (const e of n.entries) {
    if (e.value?.t === "block") throw new YamlUnread("a block scalar where a server's value is read");
    if (e.value?.t === "str") out.push({ key: e.key, value: e.value });
  }
  return out;
}

const YAML_REMOTE_TYPE_RE = /^(?:sse|streamable[_-]?http|http|https|websocket|ws)$/i;

/**
 * The server entries of Goose's `config.yaml` (`extensions:`, a map of
 * `<name>: {type, cmd, args, envs | env, env_keys, uri, headers}`; Goose's
 * ExtensionConfig) or of a Continue YAML config or block (`mcpServers:`, a
 * list of `{name, type, command, args, env, url, requestOptions.headers,
 * with}`), or null when the section holds something this reader cannot
 * read (the extractor then twins the file whole). A file with no such
 * section has no entry. Goose's `env_keys` names keys of its secret store
 * (the keyring or `secrets.yaml`), never a value. Pure.
 */
export function yamlServerEntries(content: string, kind: "goose" | "continue"): McpServerEntry[] | null {
  try {
    const sectionKey = kind === "goose" ? "extensions" : "mcpServers";
    const lines = yamlSection(content, sectionKey);
    if (lines === null) return [];
    const root = parseYamlBlock(lines);
    const section = ymap(root, sectionKey);
    if (section === null || section === undefined) return [];
    const servers: Array<{ name: string; node: YNode | null; start: number }> = [];
    if (section.t === "map") for (const e of section.entries) servers.push({ name: e.key, node: e.value, start: e.keyStart });
    else if (section.t === "seq") {
      section.items.forEach((it, idx) => {
        const n = ymap(it, "name");
        servers.push({ name: n?.t === "str" ? n.raw : `#${idx}`, node: it, start: it?.start ?? 0 });
      });
    } else return [];
    const out: McpServerEntry[] = [];
    for (const s of servers) {
      if (s.node?.t !== "map") continue;
      const values: McpValue[] = [];
      const push = (role: McpValueRole, table: string, pairs: ReturnType<typeof yamlStringPairs>): void => {
        for (const p of pairs) values.push({ role, name: p.key, start: p.value.start, end: p.value.end, raw: p.value.raw, field: `${sectionKey}.${s.name}.${table}.${p.key}` });
      };
      if (kind === "goose") {
        push("env", "envs", yamlStringPairs(ymap(s.node, "envs")));
        push("env", "env", yamlStringPairs(ymap(s.node, "env")));
      } else {
        push("env", "env", yamlStringPairs(ymap(s.node, "env")));
        push("env", "with", yamlStringPairs(ymap(s.node, "with")));
        push("header", "requestOptions.headers", yamlStringPairs(ymap(ymap(s.node, "requestOptions"), "headers")));
      }
      push("header", "headers", yamlStringPairs(ymap(s.node, "headers")));
      let url: string | null = null;
      const u = ymap(s.node, kind === "goose" ? "uri" : "url");
      if (u?.t === "str" && u.raw !== "") {
        url = u.raw;
        values.push({ role: "url", name: kind === "goose" ? "uri" : "url", start: u.start, end: u.end, raw: u.raw, field: `${sectionKey}.${s.name}.${kind === "goose" ? "uri" : "url"}` });
      }
      const type = ymap(s.node, "type");
      const remote = url !== null || (type?.t === "str" && YAML_REMOTE_TYPE_RE.test(type.raw));
      out.push({ name: s.name, start: Math.min(s.start, s.node.start), end: s.node.end, transport: remote ? "http" : "stdio", url, values });
    }
    return out;
  } catch (e) {
    if (e instanceof YamlUnread) return null;
    throw e;
  }
}

// ── TOML (Codex's config.toml) ──────────────────────────────────────────────

/** A TOML key: bare, or a basic or literal string. */
const TOML_KEY = String.raw`(?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|'[^']*')`;
export const TOML_TABLE_RE = new RegExp(String.raw`^\s*\[\s*(${TOML_KEY}(?:\s*\.\s*${TOML_KEY})*)\s*\]\s*(?:#.*)?$`);
export const TOML_PAIR_RE = new RegExp(String.raw`^(\s*)(${TOML_KEY}(?:\s*\.\s*${TOML_KEY})*)(\s*=\s*)(.*)$`);

/** The parts of a dotted TOML key, unquoted. */
export function tomlKeyParts(dotted: string): string[] {
  const re = new RegExp(TOML_KEY, "g");
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(dotted)) !== null) {
    const k = m[0];
    out.push(k.startsWith('"') ? k.slice(1, -1).replace(/\\(.)/g, "$1") : k.startsWith("'") ? k.slice(1, -1) : k);
  }
  return out;
}

/** A TOML string value at the start of `s` (at absolute offset `at`): its
 *  text between the quotes and the rest of the line after it. Null when
 *  `s` does not start with a one-line string. */
export function tomlString(s: string, at: number): { start: number; end: number; raw: string; rest: string } | null {
  const q = s[0];
  if (q !== '"' && q !== "'") return null;
  let j = 1;
  for (; j < s.length; j++) {
    if (q === '"' && s[j] === "\\") { j++; continue; }
    if (s[j] === q) break;
  }
  if (j >= s.length) return null;
  return { start: at + 1, end: at + j, raw: s.slice(1, j), rest: s.slice(j + 1) };
}

/** The sub-tables of a server whose values are read, by what they hold. */
const TOML_VALUE_TABLES: Readonly<Record<string, McpValueRole | null>> = {
  env: "env",
  http_headers: "header",
  // Values are the NAMES of variables Codex reads the header from.
  env_http_headers: null,
};

/** The pairs of a one-line inline table `{ k = "v", … }` starting at `s`
 *  (absolute offset `at`), or null when it is not one this reader reads in
 *  full (a nested table or array, a value that is not a string, number or
 *  boolean, no closing brace on the line). */
function tomlInlinePairs(s: string, at: number): Array<{ key: string; start: number; end: number; raw: string }> | null {
  if (s[0] !== "{") return null;
  const out: Array<{ key: string; start: number; end: number; raw: string }> = [];
  let i = 1;
  const keyRe = new RegExp(String.raw`^\s*(${TOML_KEY}(?:\s*\.\s*${TOML_KEY})*)\s*=\s*`);
  for (;;) {
    const rest = s.slice(i);
    const close = /^\s*\}/.exec(rest);
    if (close) return /^\s*(?:#.*)?$/.test(rest.slice(close[0].length)) ? out : null;
    const k = keyRe.exec(rest);
    if (k === null) return null;
    i += k[0].length;
    const v = s.slice(i);
    const str = tomlString(v, at + i);
    if (str !== null) {
      out.push({ key: tomlKeyParts(k[1]!).join("."), start: str.start, end: str.end, raw: str.raw });
      i += v.length - str.rest.length;
    } else {
      const lit = /^(?:true|false|[+-]?[0-9][0-9_.eE+-]*)/.exec(v);
      if (lit === null) return null;
      i += lit[0].length;
    }
    const sep = /^\s*,/.exec(s.slice(i));
    if (sep) { i += sep[0].length; continue; }
    const end = /^\s*\}/.exec(s.slice(i));
    if (end) continue;
    return null;
  }
}

function tomlServerEntries(content: string): McpServerEntry[] | null {
  return codexTomlReading(content)?.entries ?? null;
}

/** Codex's config read for its MCP servers: the entries, and the offsets
 *  of each inline table line this reader read in full (`env = { … }` in a
 *  server's table), which the generic TOML reader, which twins any file
 *  with an inline table whole, is then given blanked. */
export interface CodexTomlReading {
  entries: McpServerEntry[];
  inline: Array<{ start: number; end: number }>;
}

/**
 * Codex's `[mcp_servers.<name>]` entries, or null when the file holds an
 * inline table this reader cannot read in full inside an MCP server's
 * table, or a multi-line string anywhere (the extractor then twins the file
 * whole). An inline table elsewhere is the generic TOML reader's business
 * (which twins such a file whole). Pure.
 */
export function codexTomlReading(content: string): CodexTomlReading | null {
  if (/"""|'''/.test(content)) return null;
  const inline: Array<{ start: number; end: number }> = [];
  const byName = new Map<string, McpServerEntry>();
  let current: { entry: McpServerEntry; role: McpValueRole | null | "entry" } | null = null;
  let at = 0;
  for (const rawLine of content.split("\n")) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    const lineAt = at;
    at += rawLine.length + 1;
    if (/^\s*(?:#.*)?$/.test(line)) continue;
    const table = TOML_TABLE_RE.exec(line);
    if (table) {
      const parts = tomlKeyParts(table[1]!);
      if (parts[0] === "mcp_servers" && parts.length >= 2) {
        const name = parts[1]!;
        let entry = byName.get(name);
        if (entry === undefined) {
          entry = { name, start: lineAt, end: lineAt + line.length, transport: "stdio", url: null, values: [] };
          byName.set(name, entry);
        }
        const sub = parts.length === 2 ? "entry" : parts.length === 3 && parts[2]! in TOML_VALUE_TABLES ? TOML_VALUE_TABLES[parts[2]!]! : null;
        current = { entry, role: sub };
      } else {
        current = null;
      }
      continue;
    }
    if (current === null) continue;
    current.entry.end = lineAt + line.length;
    const pair = TOML_PAIR_RE.exec(line);
    if (pair === null) continue;
    const key = tomlKeyParts(pair[2]!).join(".");
    const vAt = lineAt + pair[1]!.length + pair[2]!.length + pair[3]!.length;
    const v = pair[4]!;
    if (current.role === "entry") {
      if (v.trimStart().startsWith("{")) {
        const lead = v.length - v.trimStart().length;
        const role = key in TOML_VALUE_TABLES ? TOML_VALUE_TABLES[key]! : undefined;
        // Another inline table in a server's table (none Codex documents):
        // left to the generic reader, which twins the file whole.
        if (role === undefined) continue;
        const pairs = tomlInlinePairs(v.trimStart(), vAt + lead);
        if (pairs === null) return null;
        inline.push({ start: lineAt, end: lineAt + line.length });
        if (role !== null) for (const p of pairs) current.entry.values.push({ role, name: p.key, start: p.start, end: p.end, raw: p.raw });
        continue;
      }
      const s = tomlString(v, vAt);
      if (s === null) continue;
      // A dotted key (`env.API_KEY = "…"`, `http_headers.X = "…"`).
      const dot = key.indexOf(".");
      const head = dot < 0 ? key : key.slice(0, dot);
      if (dot > 0 && head in TOML_VALUE_TABLES) {
        const role = TOML_VALUE_TABLES[head]!;
        if (role !== null) current.entry.values.push({ role, name: key.slice(dot + 1), start: s.start, end: s.end, raw: s.raw });
        continue;
      }
      if (key === "url") {
        current.entry.url = s.raw;
        current.entry.transport = "http";
        current.entry.values.push({ role: "url", name: "url", start: s.start, end: s.end, raw: s.raw });
      } else if (key === "bearer_token") {
        current.entry.values.push({ role: "bearer", name: "bearer_token", start: s.start, end: s.end, raw: s.raw });
      }
      continue;
    }
    if (current.role === null) continue;
    const s = tomlString(v, vAt);
    if (s !== null) current.entry.values.push({ role: current.role, name: key, start: s.start, end: s.end, raw: s.raw });
  }
  return { entries: [...byName.values()], inline };
}
