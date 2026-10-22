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
 *   codex           `.codex/config.toml` (`[mcp_servers.<name>]`)
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
 * and the extractor then twins the file whole (its fail-safe).
 *
 * Every walk here is linear in the text and bounded in depth.
 *
 * Mandu-new (no reference origin).
 */

/** The MCP config files Mandu knows, by what reads them. */
export type McpConfigKind = "claude" | "claude-project" | "cursor" | "vscode" | "claude-desktop" | "windsurf" | "codex";

/**
 * Which MCP config `path` is, by its name alone (no file is read), or null.
 * A name only: `.mcp.json` and `.claude.json` anywhere, the others by their
 * directory. A Codex config a `CODEX_HOME` moved out of `.codex` is read as
 * any TOML file (the generic rules mask its secret-named keys). Pure.
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
  return null;
}

/** The supported agent that reads a config of `kind` in its OWN process to
 *  start its MCP servers (Claude Code: `.claude.json`, `.mcp.json`; Codex:
 *  `config.toml`), or null for an editor's or an app's config that no
 *  supported agent reads. Pure. */
export function mcpConfigReader(kind: McpConfigKind): "claude" | "codex" | null {
  if (kind === "claude" || kind === "claude-project") return "claude";
  if (kind === "codex") return "codex";
  return null;
}

/**
 * The MCP config files a launch HOME holds at their default places (and the
 * places `CLAUDE_CONFIG_DIR` and `CODEX_HOME` move Claude Code's and Codex's
 * to: only absolute values count). The walk visits each directly, wherever
 * a prune would have kept it out (`~/.codex` is an agent store, `~/Library`
 * a pruned macOS folder). Pure.
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
  const kind = mcpConfigKind(path);
  if (kind === null) return null;
  return kind === "codex" ? tomlServerEntries(content) : jsonServerEntries(content, kind);
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

/** The server maps of a JSON MCP config (each `{name: entry}` object). */
function jsonServerMaps(root: JNode, kind: McpConfigKind): JNode[] {
  const maps: JNode[] = [];
  const add = (m: JNode | undefined): void => { if (m?.t === "obj") maps.push(m); };
  add(field(root, "mcpServers"));
  add(field(root, "servers"));
  add(field(field(root, "mcp"), "servers"));
  if (kind === "claude") {
    const projects = field(root, "projects");
    if (projects?.t === "obj") for (const p of projects.entries) add(field(p.value, "mcpServers"));
  }
  return maps;
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
  for (const map of jsonServerMaps(root, kind)) {
    if (map.t !== "obj") continue;
    for (const { key: name, value: entry } of map.entries) {
      if (entry.t !== "obj") continue;
      const values: McpValue[] = [];
      for (const p of stringPairs(field(entry, "env"))) values.push({ role: "env", name: p.key, start: p.value.start, end: p.value.end, raw: p.value.raw });
      for (const p of stringPairs(field(entry, "headers"))) values.push({ role: "header", name: p.key, start: p.value.start, end: p.value.end, raw: p.value.raw });
      let url: string | null = null;
      for (const k of ["url", "serverUrl", "httpUrl"]) {
        const u = field(entry, k);
        if (u?.t === "str") {
          url = u.raw;
          values.push({ role: "url", name: k, start: u.start, end: u.end, raw: u.raw });
        }
      }
      const type = field(entry, "type") ?? field(entry, "transport");
      const remote = url !== null || (type?.t === "str" && REMOTE_TYPE_RE.test(type.raw));
      out.push({ name, start: entry.start, end: entry.end, transport: remote ? "http" : "stdio", url, values });
    }
  }
  return out;
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
