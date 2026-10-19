/**
 * mcp-server-config — which third-party STDIO MCP servers the launched agent
 * is configured with, told to the arbiter before the agent starts
 * (confidentiality plan 10 §11.13), and again whenever one of the files the
 * read consulted changes during the session (§11.17: `watchMcpConfig`; each
 * registration carries the files and their stamps, and the arbiter keeps
 * every server from `clean` while a stamp has moved).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 *
 * Why: a STDIO MCP server is a child process the agent spawns, and the
 * guard records every exec's argv. Given each configured server's
 * `{name, command, args}`, the arbiter can map a tool namespace
 * (`mcp__<name>__*` for Claude Code, `<name>` for Codex) to the process the
 * agent spawned for it. A server this list does not name stays UNMAPPED and
 * its results fall back to the session rule, the fail-closed reading; so
 * over-inclusion (a scope the agent does not load, the same name from two
 * scopes) is harmless and every source is read.
 *
 * What is read (never written; a missing, unreadable or malformed file
 * contributes nothing, and nothing here throws):
 *   - claude: `<CLAUDE_CONFIG_DIR or HOME>/.claude.json`: the top-level
 *     `mcpServers` (user scope) and `projects[<cwd>].mcpServers` (local
 *     scope) for the human's cwd and the AgentView cwd; `<cwd>/.mcp.json`
 *     `mcpServers` (project scope) for the same two directories. Since
 *     2026-10-02 also the managed file (`/etc/claude-code/managed-mcp.json`
 *     on Linux), every installed plugin's servers (`<CLAUDE_CONFIG_DIR or
 *     HOME/.claude>/plugins/installed_plugins.json` → each install's
 *     `.mcp.json` and `.claude-plugin/plugin.json` `mcpServers`, named
 *     `plugin:<plugin>:<server>` with `${CLAUDE_PLUGIN_ROOT}` put in), and
 *     each `--mcp-config <file or JSON>` on the agent's own argv.
 *   - codex: `<CODEX_HOME or HOME/.codex>/config.toml` `mcp_servers.<name>`
 *     (a small strict TOML reader below: launcher config.ts `parseToml` is a
 *     flat key reader that skips every table), and since 2026-10-02 the
 *     agent's own `-c` / `--config mcp_servers.…` overrides, laid over it.
 *   - any other target: none.
 * A STDIO server is an entry with a non-empty string `command`; `args` is
 * absent (→ []) or an array of strings, else the entry is skipped. Entries
 * with a `url`, or a `type` other than "stdio" (http, sse, ws, …), are
 * remote servers with no local process and are skipped. Mandu's own servers
 * (`mandu-inspect`, `mandu-policy`: services/mcp.ts) are left out: the
 * arbiter exempts them anyway.
 *
 * Why the HUMAN plane (docs/design/architecture/arbiter-human-plane.md): the mapping
 * decides how the results of a tool namespace are treated, so only the
 * launcher, outside the agent's reach, may set it. `registerMcpServers` is
 * a human-plane op; the agent world cannot reach that socket, so a process
 * inside the agent can never register (or re-register) a server of its own
 * choosing. With no human socket the call is skipped and the servers stay
 * unmapped (the fail-closed fallback); the data socket is never used.
 */
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { LaunchPlan } from "./types.js";

/** One configured STDIO MCP server, with the file and key it came from. */
export interface ConfiguredMcpServer {
  name: string;
  command: string;
  args: string[];
  /** `<file>#<key path>`, for notes and tests. Not sent to the arbiter. */
  source: string;
  /** Codex only: the entry's own `env_vars` (the parent variables Codex
   *  forwards to the server), when it has a readable one. Not sent. */
  envVars?: string[];
  /** Codex only: the entry has an `env_vars` this reader cannot read (not an
   *  array of strings), so nothing may be added to it. Not sent. */
  envVarsUnreadable?: boolean;
}

export interface McpConfigInput {
  target: "claude" | "codex" | string;
  /** The launch's HOME. */
  home: string;
  /** `$CLAUDE_CONFIG_DIR`, where Claude Code then keeps `.claude.json`. */
  claudeConfigDir?: string;
  /** `$CODEX_HOME`, else `<home>/.codex`. */
  codexHome?: string;
  /** The human's launch directory (LaunchPlan.humanCwd). */
  humanCwd: string;
  /** The directory the agent runs in (LaunchPlan.cwd: the AgentView when
   *  the fs view is on, else the same as humanCwd). */
  agentCwd: string;
  /** Read a file as UTF-8, null when absent or unreadable (default: fs). */
  readFile?: (p: string) => string | null;
  /** The agent's own command and arguments (LaunchPlan.argv): Claude Code's
   *  `--mcp-config`, Codex's `-c mcp_servers.…`. Absent: none read. */
  agentArgv?: readonly string[];
  /** Claude Code's managed MCP file (default: the platform's). */
  managedMcpFile?: string;
}

/** Claude Code's managed MCP file, by platform (an administrator's, root-owned). */
export function defaultManagedMcpFile(platform: string = process.platform): string {
  if (platform === "darwin") return "/Library/Application Support/ClaudeCode/managed-mcp.json";
  if (platform === "win32") return "C:\\Program Files\\ClaudeCode\\managed-mcp.json";
  return "/etc/claude-code/managed-mcp.json";
}

/** Mandu's own MCP servers (services/mcp.ts: the inspect-mcp entry and
 *  MANDU_POLICY_SERVER), never reported: the arbiter exempts them. */
export const MANDU_OWN_MCP_SERVERS: readonly string[] = ["mandu-inspect", "mandu-policy"];

function defaultReadFile(p: string): string | null {
  try {
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

const nonEmpty = (s: string | undefined): s is string => typeof s === "string" && s !== "";

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** The STDIO entries of one `mcpServers` / `mcp_servers` map. Pure. */
export function stdioServersOf(map: unknown, source: string): ConfiguredMcpServer[] {
  if (!isPlainObject(map)) return [];
  const out: ConfiguredMcpServer[] = [];
  for (const name of Object.keys(map)) {
    if (name === "" || MANDU_OWN_MCP_SERVERS.includes(name)) continue;
    const e = map[name];
    if (!isPlainObject(e)) continue;
    if (own(e, "url")) continue;
    if (own(e, "type") && e["type"] !== "stdio") continue;
    const command = e["command"];
    if (typeof command !== "string" || command === "") continue;
    let args: string[] = [];
    if (own(e, "args") && e["args"] !== undefined) {
      const a = e["args"];
      if (!Array.isArray(a) || !a.every((x) => typeof x === "string")) continue;
      args = [...(a as string[])];
    }
    const server: ConfiguredMcpServer = { name, command, args, source };
    if (own(e, "env_vars") && e["env_vars"] !== undefined) {
      const v = e["env_vars"];
      if (Array.isArray(v) && v.every((x) => typeof x === "string")) server.envVars = [...(v as string[])];
      else server.envVarsUnreadable = true;
    }
    out.push(server);
  }
  return out;
}

function readJson(path: string, read: (p: string) => string | null): unknown {
  const text = read(path);
  if (text === null) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function claudeServers(input: McpConfigInput, read: (p: string) => string | null): ConfiguredMcpServer[] {
  const out: ConfiguredMcpServer[] = [];
  const cwds = [...new Set([input.humanCwd, input.agentCwd].filter(nonEmpty))];
  const userFile = join(nonEmpty(input.claudeConfigDir) ? input.claudeConfigDir : input.home, ".claude.json");
  const doc = readJson(userFile, read);
  if (isPlainObject(doc)) {
    out.push(...stdioServersOf(doc["mcpServers"], `${userFile}#mcpServers`));
    const projects = doc["projects"];
    if (isPlainObject(projects)) {
      for (const cwd of cwds) {
        if (!own(projects, cwd)) continue;
        const p = projects[cwd];
        if (isPlainObject(p)) out.push(...stdioServersOf(p["mcpServers"], `${userFile}#projects[${cwd}].mcpServers`));
      }
    }
  }
  for (const cwd of cwds) {
    const file = join(cwd, ".mcp.json");
    const proj = readJson(file, read);
    if (isPlainObject(proj)) out.push(...stdioServersOf(proj["mcpServers"], `${file}#mcpServers`));
  }
  const managed = nonEmpty(input.managedMcpFile) ? input.managedMcpFile : defaultManagedMcpFile();
  const mdoc = readJson(managed, read);
  if (isPlainObject(mdoc)) out.push(...stdioServersOf(mdoc["mcpServers"], `${managed}#mcpServers`));
  out.push(...claudePluginServers(join(nonEmpty(input.claudeConfigDir) ? input.claudeConfigDir : join(input.home, ".claude"), "plugins", "installed_plugins.json"), read));
  out.push(...claudeArgvServers(input.agentArgv ?? [], input.humanCwd, read));
  return out;
}

/** A server map from an MCP config document: its `mcpServers`, else the
 *  document itself (a plugin's `.mcp.json` may hold the map bare). */
function serverMapOf(doc: unknown): unknown {
  return isPlainObject(doc) && isPlainObject(doc["mcpServers"]) ? doc["mcpServers"] : doc;
}

/**
 * Every installed Claude Code plugin's STDIO servers (installed_plugins.json
 * v2 `{plugins: {"<name>@<marketplace>": [{installPath, …}]}}`, v1
 * `{plugins: {"<name>": {installPath, …}}}`): the install's `.mcp.json` and
 * its manifest's `mcpServers` (a map, a path relative to the install, or an
 * array of either). Named `plugin:<plugin>:<server>` (the tool namespace is
 * `mcp__plugin_<plugin>_<server>__`), `${CLAUDE_PLUGIN_ROOT}` replaced by the
 * install path. Pure over `read`.
 */
export function claudePluginServers(registry: string, read: (p: string) => string | null): ConfiguredMcpServer[] {
  const doc = readJson(registry, read);
  if (!isPlainObject(doc) || !isPlainObject(doc["plugins"])) return [];
  const out: ConfiguredMcpServer[] = [];
  for (const [key, val] of Object.entries(doc["plugins"] as Record<string, unknown>)) {
    const plugin = key.includes("@") ? key.slice(0, key.indexOf("@")) : key;
    if (plugin === "") continue;
    const installs = Array.isArray(val) ? val : [val];
    for (const inst of installs) {
      if (!isPlainObject(inst) || typeof inst["installPath"] !== "string" || inst["installPath"] === "") continue;
      const root = inst["installPath"] as string;
      const maps: Array<{ map: unknown; source: string }> = [];
      const mcpFile = join(root, ".mcp.json");
      maps.push({ map: serverMapOf(readJson(mcpFile, read)), source: mcpFile });
      const manifestFile = join(root, ".claude-plugin", "plugin.json");
      const manifest = readJson(manifestFile, read);
      const decl = isPlainObject(manifest) ? manifest["mcpServers"] : undefined;
      for (const d of Array.isArray(decl) ? decl : decl === undefined ? [] : [decl]) {
        if (typeof d === "string" && d !== "" && !/^[a-z]+:\/\//i.test(d)) {
          const f = join(root, d);
          maps.push({ map: serverMapOf(readJson(f, read)), source: f });
        } else if (isPlainObject(d)) {
          maps.push({ map: d, source: `${manifestFile}#mcpServers` });
        }
      }
      const sub = (v: string): string => v.split("${CLAUDE_PLUGIN_ROOT}").join(root);
      for (const { map, source } of maps) {
        for (const sv of stdioServersOf(map, source)) {
          out.push({ ...sv, name: `plugin:${plugin}:${sv.name}`, command: sub(sv.command), args: sv.args.map(sub) });
        }
      }
    }
  }
  return out;
}

/** Claude Code's `--mcp-config <configs...>` (and `--mcp-config=<one>`):
 *  each value a JSON file (relative to the launch directory) or a JSON
 *  string, holding `mcpServers`. Variadic: values run to the next option. */
export function claudeArgvServers(argv: readonly string[], cwd: string, read: (p: string) => string | null): ConfiguredMcpServer[] {
  const values: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") break;
    if (a.startsWith("--mcp-config=")) { values.push(a.slice("--mcp-config=".length)); continue; }
    if (a !== "--mcp-config") continue;
    while (i + 1 < argv.length && !argv[i + 1]!.startsWith("-")) values.push(argv[++i]!);
  }
  const out: ConfiguredMcpServer[] = [];
  for (const v of values) {
    const t = v.trim();
    let doc: unknown;
    let source: string;
    if (t.startsWith("{")) {
      try { doc = JSON.parse(t) as unknown; } catch { continue; }
      source = "--mcp-config <json>";
    } else {
      const f = t.startsWith("/") ? t : join(cwd, t);
      doc = readJson(f, read);
      source = `--mcp-config ${f}`;
    }
    if (isPlainObject(doc)) out.push(...stdioServersOf(doc["mcpServers"], `${source}#mcpServers`));
  }
  return out;
}

/** Codex's `-c key=value` / `--config key=value` (and `--config=key=value`)
 *  overrides whose key starts `mcp_servers.`: each value read as TOML, else
 *  as a literal string (as codex does), laid over `doc` by its dotted key.
 *  Returns the merged document (a copy; `doc` is not changed). */
export function withCodexArgvOverrides(doc: Record<string, unknown>, argv: readonly string[]): Record<string, unknown> {
  const pairs: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") break;
    if ((a === "-c" || a === "--config") && i + 1 < argv.length) pairs.push(argv[++i]!);
    else if (a.startsWith("--config=")) pairs.push(a.slice("--config=".length));
    else if (a.startsWith("-c") && a.length > 2 && !a.startsWith("--")) pairs.push(a.slice(2));
  }
  const merged = structuredClone(doc) as Record<string, unknown>;
  for (const pair of pairs) {
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const key = pair.slice(0, eq).trim();
    if (!key.startsWith("mcp_servers.")) continue;
    const raw = pair.slice(eq + 1);
    // A value that does not open as TOML (a bare word) is a string, as codex
    // reads it; this reader would keep a bare word as a raw scalar.
    const tomlish = /^\s*(["'[{]|[-+]?[0-9]|true\b|false\b|[-+]?(inf|nan)\b)/.test(raw);
    const parsed = (tomlish ? parseTomlDocument(`${key} = ${raw}`) : null) ?? parseTomlDocument(`${key} = ${JSON.stringify(raw)}`);
    if (parsed === null) continue;
    deepAssign(merged, parsed);
  }
  return merged;
}

function deepAssign(into: Record<string, unknown>, from: Record<string, unknown>): void {
  for (const [k, v] of Object.entries(from)) {
    const cur = into[k];
    if (v !== null && typeof v === "object" && !Array.isArray(v) && Object.getPrototypeOf(v) === null && cur !== null && typeof cur === "object" && !Array.isArray(cur)) {
      deepAssign(cur as Record<string, unknown>, v as Record<string, unknown>);
    } else {
      into[k] = v;
    }
  }
}

function codexServers(input: McpConfigInput, read: (p: string) => string | null): ConfiguredMcpServer[] {
  const file = join(nonEmpty(input.codexHome) ? input.codexHome : join(input.home, ".codex"), "config.toml");
  const text = read(file);
  const doc = text === null ? null : parseTomlDocument(text);
  const out = doc === null ? [] : stdioServersOf(doc["mcp_servers"], `${file}#mcp_servers`);
  // The agent's own `-c mcp_servers.…` overrides, laid over the file (an
  // unreadable file contributes nothing but the overrides still apply). A
  // server whose override changed its command line is registered with both
  // (over-inclusion only widens the candidates).
  const argv = input.agentArgv ?? [];
  if (argv.length > 0) {
    const merged = withCodexArgvOverrides(doc ?? (Object.create(null) as Record<string, unknown>), argv);
    for (const sv of stdioServersOf(merged["mcp_servers"], "codex -c mcp_servers")) {
      if (!out.some((o) => o.name === sv.name && o.command === sv.command && o.args.length === sv.args.length && o.args.every((x, i) => x === sv.args[i]))) out.push(sv);
    }
  }
  return out;
}

/**
 * Every STDIO MCP server the agent `target` is configured with (see the
 * header for the sources). Never throws; order: user scope, local scope,
 * project scope (Claude Code), or file order (Codex).
 */
export function configuredMcpServers(input: McpConfigInput): ConfiguredMcpServer[] {
  const read = input.readFile ?? defaultReadFile;
  try {
    if (input.target === "claude") return claudeServers(input, read);
    if (input.target === "codex") return codexServers(input, read);
  } catch {
    // Defensive: every reader above already contributes nothing on a bad file.
  }
  return [];
}

// ---------------------------------------------------------------------------
// A small strict TOML reader: tables, arrays of tables, dotted keys, bare /
// basic / literal keys, basic / literal / multi-line strings, arrays and inline
// tables (both may span lines). Booleans are read as booleans; the other
// scalars (numbers, dates) as a `TomlScalar` holding their raw text, never as a
// string, so `args = ["a", 1]` is not an array of strings. Only strings and
// string arrays are read from it. Anything it cannot read makes the whole document null (the file
// contributes nothing). Tables are null-prototype objects.

class TomlError extends Error {}

/** A number or date, kept as written (not a string: see above). */
export class TomlScalar {
  constructor(readonly raw: string) {}
}

type Table = Record<string, unknown>;
const newTable = (): Table => Object.create(null) as Table;
/** Only the reader's own (null-prototype) tables: never an array or a TomlScalar. */
const isTable = (v: unknown): v is Table => v !== null && typeof v === "object" && Object.getPrototypeOf(v) === null;

/** Parse a TOML document, or null when it is not one this reader can read. Pure. */
export function parseTomlDocument(text: string): Record<string, unknown> | null {
  try {
    return new TomlReader(text).document();
  } catch {
    return null; // TomlError, or a RangeError from a bad \U code point
  }
}

class TomlReader {
  private i = 0;
  constructor(private readonly s: string) {}

  private fail(why: string): never {
    throw new TomlError(`${why} at offset ${this.i}`);
  }
  private peek(off = 0): string {
    return this.s[this.i + off] ?? "";
  }
  private startsWith(t: string): boolean {
    return this.s.startsWith(t, this.i);
  }
  /** Spaces and tabs. */
  private ws(): void {
    while (this.peek() === " " || this.peek() === "\t") this.i++;
  }
  private comment(): void {
    if (this.peek() !== "#") return;
    while (this.i < this.s.length && this.peek() !== "\n") this.i++;
  }
  /** Whitespace, comments and newlines (between statements, inside arrays). */
  private blank(): void {
    for (;;) {
      this.ws();
      this.comment();
      if (this.peek() === "\n") { this.i++; continue; }
      if (this.startsWith("\r\n")) { this.i += 2; continue; }
      return;
    }
  }
  /** The end of a statement: optional whitespace and comment, then a newline or EOF. */
  private endOfLine(): void {
    this.ws();
    this.comment();
    if (this.i >= this.s.length) return;
    if (this.peek() === "\n") { this.i++; return; }
    if (this.startsWith("\r\n")) { this.i += 2; return; }
    this.fail("expected end of line");
  }

  document(): Table {
    const root = newTable();
    let current = root;
    for (;;) {
      this.blank();
      if (this.i >= this.s.length) return root;
      if (this.startsWith("[[")) {
        this.i += 2;
        const path = this.keyPath();
        if (!this.startsWith("]]")) this.fail("expected ]]");
        this.i += 2;
        const parent = this.descend(root, path.slice(0, -1));
        const last = path[path.length - 1]!;
        let arr = parent[last];
        if (arr === undefined) { arr = []; parent[last] = arr; }
        if (!Array.isArray(arr)) this.fail("array of tables over a value");
        const t = newTable();
        (arr as unknown[]).push(t);
        current = t;
      } else if (this.peek() === "[") {
        this.i++;
        const path = this.keyPath();
        if (this.peek() !== "]") this.fail("expected ]");
        this.i++;
        current = this.descend(root, path);
      } else {
        const path = this.keyPath();
        if (this.peek() !== "=") this.fail("expected =");
        this.i++;
        this.ws();
        const value = this.value();
        this.assign(current, path, value);
      }
      this.endOfLine();
    }
  }

  /** Walk (creating) the tables along `path`; an array of tables descends
   *  into its last element. */
  private descend(from: Table, path: string[]): Table {
    let t = from;
    for (const k of path) {
      let next = t[k];
      if (next === undefined) { next = newTable(); t[k] = next; }
      if (Array.isArray(next)) next = next[next.length - 1];
      if (!isTable(next)) this.fail(`key ${k} is not a table`);
      t = next as Table;
    }
    return t;
  }

  private assign(into: Table, path: string[], value: unknown): void {
    const parent = this.descend(into, path.slice(0, -1));
    const last = path[path.length - 1]!;
    if (Object.prototype.hasOwnProperty.call(parent, last)) this.fail(`duplicate key ${last}`);
    parent[last] = value;
  }

  /** `a.b."c d".'e'` with optional whitespace around the dots; ends after
   *  trailing whitespace. */
  private keyPath(): string[] {
    const out: string[] = [];
    for (;;) {
      this.ws();
      out.push(this.key());
      this.ws();
      if (this.peek() !== ".") return out;
      this.i++;
    }
  }

  private key(): string {
    const c = this.peek();
    if (c === '"') {
      if (this.startsWith('"""')) this.fail("multi-line key");
      return this.basicString();
    }
    if (c === "'") {
      if (this.startsWith("'''")) this.fail("multi-line key");
      return this.literalString();
    }
    const start = this.i;
    while (/[A-Za-z0-9_-]/.test(this.peek())) this.i++;
    if (this.i === start) this.fail("expected a key");
    return this.s.slice(start, this.i);
  }

  private value(): unknown {
    const c = this.peek();
    if (this.startsWith('"""')) return this.multiBasicString();
    if (this.startsWith("'''")) return this.multiLiteralString();
    if (c === '"') return this.basicString();
    if (c === "'") return this.literalString();
    if (c === "[") return this.array();
    if (c === "{") return this.inlineTable();
    return this.scalar();
  }

  private array(): unknown[] {
    this.i++; // [
    const out: unknown[] = [];
    for (;;) {
      this.blank();
      if (this.peek() === "]") { this.i++; return out; }
      if (this.i >= this.s.length) this.fail("unterminated array");
      out.push(this.value());
      this.blank();
      if (this.peek() === ",") { this.i++; continue; }
      if (this.peek() === "]") { this.i++; return out; }
      this.fail("expected , or ]");
    }
  }

  private inlineTable(): Table {
    this.i++; // {
    const t = newTable();
    this.blank();
    if (this.peek() === "}") { this.i++; return t; }
    for (;;) {
      this.blank();
      const path = this.keyPath();
      if (this.peek() !== "=") this.fail("expected =");
      this.i++;
      this.ws();
      this.assign(t, path, this.value());
      this.blank();
      if (this.peek() === ",") { this.i++; this.blank(); if (this.peek() === "}") { this.i++; return t; } continue; }
      if (this.peek() === "}") { this.i++; return t; }
      this.fail("expected , or }");
    }
  }

  /** Booleans as booleans; numbers and dates as a TomlScalar. */
  private scalar(): unknown {
    const start = this.i;
    while (/[A-Za-z0-9_+\-.:]/.test(this.peek())) this.i++;
    // A date-time's space separator: `1979-05-27 07:32:00`.
    if (this.peek() === " " && /^\d{4}-\d{2}-\d{2}$/.test(this.s.slice(start, this.i)) && /\d/.test(this.peek(1))) {
      this.i++;
      while (/[A-Za-z0-9_+\-.:]/.test(this.peek())) this.i++;
    }
    const raw = this.s.slice(start, this.i);
    if (raw === "") this.fail("expected a value");
    if (raw === "true") return true;
    if (raw === "false") return false;
    return new TomlScalar(raw);
  }

  private escape(): string {
    const c = this.peek();
    this.i++;
    switch (c) {
      case "b": return "\b";
      case "t": return "\t";
      case "n": return "\n";
      case "f": return "\f";
      case "r": return "\r";
      case "e": return "\x1b";
      case '"': return '"';
      case "\\": return "\\";
      case "u":
      case "U": {
        const n = c === "u" ? 4 : 8;
        const hex = this.s.slice(this.i, this.i + n);
        if (!new RegExp(`^[0-9A-Fa-f]{${n}}$`).test(hex)) this.fail("bad unicode escape");
        this.i += n;
        return String.fromCodePoint(parseInt(hex, 16)); // RangeError on a bad code point
      }
      default:
        return this.fail("bad escape");
    }
  }

  private basicString(): string {
    this.i++; // "
    let out = "";
    for (;;) {
      const c = this.peek();
      if (c === "" || c === "\n" || c === "\r") this.fail("unterminated string");
      this.i++;
      if (c === '"') return out;
      out += c === "\\" ? this.escape() : c;
    }
  }

  private literalString(): string {
    this.i++; // '
    const start = this.i;
    for (;;) {
      const c = this.peek();
      if (c === "" || c === "\n" || c === "\r") this.fail("unterminated string");
      if (c === "'") { const v = this.s.slice(start, this.i); this.i++; return v; }
      this.i++;
    }
  }

  /** A newline right after the opening delimiter is trimmed. */
  private skipFirstNewline(): void {
    if (this.peek() === "\n") this.i++;
    else if (this.startsWith("\r\n")) this.i += 2;
  }

  /** The closing delimiter may be followed by up to two more quotes, which
   *  belong to the content. */
  private closeMulti(q: string): string | null {
    if (!this.startsWith(q + q + q)) return null;
    let extra = "";
    this.i += 3;
    while (extra.length < 2 && this.peek() === q) { extra += q; this.i++; }
    return extra;
  }

  private multiBasicString(): string {
    this.i += 3;
    this.skipFirstNewline();
    let out = "";
    for (;;) {
      if (this.i >= this.s.length) this.fail("unterminated string");
      const end = this.closeMulti('"');
      if (end !== null) return out + end;
      const c = this.peek();
      if (c === "\\") {
        // A line-ending backslash trims the newline and following whitespace.
        let j = this.i + 1;
        while (this.s[j] === " " || this.s[j] === "\t") j++;
        if (this.s[j] === "\n" || (this.s[j] === "\r" && this.s[j + 1] === "\n")) {
          this.i = j;
          while (/[ \t\r\n]/.test(this.peek())) this.i++;
          continue;
        }
        this.i++;
        out += this.escape();
        continue;
      }
      out += c;
      this.i++;
    }
  }

  private multiLiteralString(): string {
    this.i += 3;
    this.skipFirstNewline();
    let out = "";
    for (;;) {
      if (this.i >= this.s.length) this.fail("unterminated string");
      const end = this.closeMulti("'");
      if (end !== null) return out + end;
      out += this.peek();
      this.i++;
    }
  }
}

// ---------------------------------------------------------------------------
// Registration on the arbiter's human plane.

export interface McpRegistrationDeps {
  /** One request on a socket (secret-setup.ts `ndjsonCall`). */
  call: (sock: string, op: string, args: Record<string, unknown>) => Promise<unknown>;
  /** The launch's note channel (stderr, kept in launch.log). */
  log: (m: string) => void;
}

export type McpRegistration =
  | { status: "registered"; registered: number }
  /** Nothing to register: no call is made. */
  | { status: "none" }
  /** No human socket: not sent, the servers stay unmapped. */
  | { status: "skipped" }
  | { status: "failed"; reason: string };

const UNMAPPED_TAIL = "their results fall back to the session rule";

/**
 * Tell the arbiter, on its HUMAN-PLANE socket, which STDIO MCP servers this
 * session's agent is configured with (`registerMcpServers {sessionKey,
 * servers, sources?}` → `{registered}`). Best-effort: never throws, never
 * refuses the launch; a failure (or no human socket) leaves the servers
 * unmapped, which the arbiter treats as the fail-closed fallback, and logs one
 * WARNING. Only `{name, command, args}` and the read's `sources` (path and
 * stamp) are sent. With no servers, nothing is sent unless `always` (a
 * re-read whose sources must replace an earlier registration's).
 */
export async function registerMcpServers(
  humanSock: string | null | undefined,
  sessionKey: string,
  servers: readonly ConfiguredMcpServer[],
  deps: McpRegistrationDeps,
  opts: { sources?: readonly McpConfigSource[]; always?: boolean } = {},
): Promise<McpRegistration> {
  if (servers.length === 0 && opts.always !== true) return { status: "none" };
  const names = [...new Set(servers.map((s) => s.name))].join(", ") || "none";
  if (!humanSock) {
    deps.log(`WARNING: mandu: MCP servers not mapped (${names}): the protection service reported no human-plane socket; ${UNMAPPED_TAIL}`);
    return { status: "skipped" };
  }
  const fail = (reason: string): McpRegistration => {
    deps.log(`WARNING: mandu: MCP servers not mapped (${names}): ${reason}; ${UNMAPPED_TAIL}`);
    return { status: "failed", reason };
  };
  try {
    const r = (await deps.call(humanSock, "registerMcpServers", {
      sessionKey,
      servers: servers.map((s) => ({ name: s.name, command: s.command, args: [...s.args] })),
      ...(opts.sources ? { sources: opts.sources.map((x) => ({ path: x.path, stamp: x.stamp })) } : {}),
    })) as { registered?: unknown } | null;
    if (r === null || typeof r !== "object" || typeof r.registered !== "number") {
      return fail("the protection service's answer is not {registered}");
    }
    return { status: "registered", registered: r.registered };
  } catch (e) {
    return fail(e instanceof Error ? e.message : String(e));
  }
}

// ---------------------------------------------------------------------------
// Following the config through the session (plan 10 §11.17).

/** One file the read consulted, with its stamp when it was read. */
export interface McpConfigSource {
  path: string;
  stamp: string;
}

/** A read of the agent's MCP config: the servers, and every file consulted. */
export interface McpConfigRead {
  servers: ConfiguredMcpServer[];
  sources: McpConfigSource[];
}

/** The arbiter's cap on `sources` (server.ts registerMcpServers). */
export const MCP_SOURCES_MAX = 256;

/**
 * Plan 10 §11.17: a config file's stamp. A MIRROR of arbiter/ipc/server.ts
 * `mcpSourceStamp` (this package takes no arbiter import;
 * tests/stack/mcp-server-taint.test.ts pins the two to one answer):
 * `<dev>:<ino>:<size>:<mtime ns>:<ctime ns>` of what the path names (links
 * followed), `absent` when nothing is there, `unreadable` on any other
 * error. Never throws.
 */
export function mcpSourceStamp(path: string): string {
  try {
    const st = statSync(path, { bigint: true });
    return `${st.dev}:${st.ino}:${st.size}:${st.mtimeNs}:${st.ctimeNs}`;
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    return code === "ENOENT" || code === "ENOTDIR" ? "absent" : "unreadable";
  }
}

/**
 * {@link configuredMcpServers}, also returning every file it consulted, each
 * stamped BEFORE it was read: a write that lands between the stamp and the
 * read leaves the arbiter's check seeing a moved stamp (fail-closed until the
 * next re-read), never a stamp that vouches for content it did not see. A
 * file that is absent is a source too (a `.mcp.json` created later changes
 * the mapping). Over the arbiter's cap, a source no path can match is added,
 * so the check never passes on a list it could not hold whole.
 */
export function readMcpConfig(input: McpConfigInput & { stamp?: (p: string) => string }): McpConfigRead {
  const read = input.readFile ?? defaultReadFile;
  const stamp = input.stamp ?? mcpSourceStamp;
  const seen = new Map<string, string>();
  const recording = (p: string): string | null => {
    if (!seen.has(p)) seen.set(p, stamp(p));
    return read(p);
  };
  const servers = configuredMcpServers({ ...input, readFile: recording });
  let sources = [...seen].filter(([p]) => p.startsWith("/")).map(([path, st]) => ({ path, stamp: st }));
  if (sources.length > MCP_SOURCES_MAX) {
    sources = [...sources.slice(0, MCP_SOURCES_MAX - 1), { path: "/", stamp: "overflow" }];
  }
  return { servers, sources };
}

/** The plan fields the launch-time registration reads. */
export type McpLaunchPlan = Pick<LaunchPlan, "target" | "scopeId" | "humanCwd" | "cwd" | "arbiterHumanSock" | "effectiveAxes" | "confidentiality"> & Partial<Pick<LaunchPlan, "argv">>;

type ReadDeps = { home: string; readFile?: (p: string) => string | null; stamp?: (p: string) => string };

function launchConfigInput(plan: McpLaunchPlan, env: Record<string, string | undefined>, deps: ReadDeps): McpConfigInput & { stamp?: (p: string) => string } {
  return {
    target: plan.target,
    home: deps.home,
    ...(nonEmpty(env["CLAUDE_CONFIG_DIR"]) ? { claudeConfigDir: env["CLAUDE_CONFIG_DIR"] } : {}),
    ...(nonEmpty(env["CODEX_HOME"]) ? { codexHome: env["CODEX_HOME"] } : {}),
    humanCwd: plan.humanCwd,
    agentCwd: plan.cwd,
    ...(plan.argv ? { agentArgv: plan.argv.slice(1) } : {}),
    ...(deps.readFile ? { readFile: deps.readFile } : {}),
    ...(deps.stamp ? { stamp: deps.stamp } : {}),
  };
}

/**
 * The launch's step (run.ts, before the agent starts): with the
 * confidentiality axis on, read the agent's configured STDIO MCP servers and
 * register them, with the files the read consulted, under the session key
 * `plan.scopeId` (the key the context proxies, inspect-mcp and the guard use)
 * on `plan.arbiterHumanSock`. Null when the axis is off (nothing to map).
 * Never throws. run.ts uses {@link mapLaunchMcpServers}, which also returns
 * the session's watch.
 */
export async function registerLaunchMcpServers(
  plan: McpLaunchPlan,
  env: Record<string, string | undefined>,
  deps: McpRegistrationDeps & ReadDeps,
): Promise<McpRegistration | null> {
  return (await mapLaunchMcpServers(plan, env, deps)).registration;
}

/** The session's watch over its MCP config (plan 10 §11.17). */
export interface McpConfigWatch {
  /** Re-read and re-register when a source's stamp moved. True when a
   *  registration was sent and accepted. Never throws. */
  checkNow(): Promise<boolean>;
  start(): void;
  stop(): void;
}

/** How often the watch stats the config files (ms). */
export const MCP_CONFIG_WATCH_INTERVAL_MS = 500;

/**
 * Plan 10 §11.17: follow the agent's MCP config through the session. Every
 * `intervalMs` each source of the last accepted read is stamped; when one
 * moved (an edit, a rename-write, a file created or removed) the config is
 * read again and registered with its new sources (`always`: a config that now
 * names no server still replaces the stamps). The arbiter's registration is
 * add-only, so a server whose command line changed is then named by both and
 * its old process can no longer vouch for it alone; between the write and the
 * re-read the arbiter's own stamp check keeps the session's servers from
 * `clean`. A registration that fails is retried on the next tick (the last
 * accepted read is kept). Polling, not a file watch: Claude Code rewrites
 * `.claude.json` by rename, which a watch on the file does not follow.
 */
export function watchMcpConfig(
  input: McpConfigInput & { stamp?: (p: string) => string },
  initial: McpConfigRead,
  humanSock: string,
  sessionKey: string,
  deps: McpRegistrationDeps & { intervalMs?: number; registered?: boolean },
): McpConfigWatch {
  const stamp = input.stamp ?? mcpSourceStamp;
  let last = initial;
  let registered = deps.registered === true;
  let timer: ReturnType<typeof setInterval> | null = null;
  let busy: Promise<boolean> | null = null;
  let warned = false;
  // One WARNING per session: a failing arbiter would repeat it every tick.
  const onceLog = (m: string): void => {
    if (warned) return;
    warned = true;
    deps.log(m);
  };
  const check = async (): Promise<boolean> => {
    if (!last.sources.some((x) => stamp(x.path) !== x.stamp)) return false;
    const next = readMcpConfig(input);
    if (next.servers.length === 0 && !registered) {
      // Nothing was ever mapped and nothing is now: nothing to replace.
      last = next;
      return false;
    }
    const r = await registerMcpServers(humanSock, sessionKey, next.servers, { call: deps.call, log: onceLog }, { sources: next.sources, always: true });
    if (r.status !== "registered") return false;
    last = next;
    registered = true;
    return true;
  };
  const checkNow = (): Promise<boolean> => {
    if (busy !== null) return busy;
    const run = check().catch(() => false).finally(() => { busy = null; });
    busy = run;
    return run;
  };
  return {
    checkNow,
    start(): void {
      if (timer !== null) return;
      timer = setInterval(() => { void checkNow(); }, deps.intervalMs ?? MCP_CONFIG_WATCH_INTERVAL_MS);
      timer.unref?.();
    },
    stop(): void {
      if (timer !== null) clearInterval(timer);
      timer = null;
    },
  };
}

/**
 * The launch's registration and the session's watch (returned unstarted).
 * Both null when the axis is off; the watch is null with no human socket or
 * for an agent whose MCP config Mandu does not read (only Claude Code and
 * Codex are mapped per server; every other agent's MCP tools take the
 * session rule, rewrite-request.ts `unknownTools`).
 */
export async function mapLaunchMcpServers(
  plan: McpLaunchPlan,
  env: Record<string, string | undefined>,
  deps: McpRegistrationDeps & ReadDeps & { intervalMs?: number; watchLog?: (m: string) => void },
): Promise<{ registration: McpRegistration | null; watch: McpConfigWatch | null }> {
  if ((plan.effectiveAxes?.confidentiality ?? plan.confidentiality) !== true) return { registration: null, watch: null };
  const input = launchConfigInput(plan, env, deps);
  const first = readMcpConfig(input);
  const registration = await registerMcpServers(plan.arbiterHumanSock, plan.scopeId, first.servers, deps, { sources: first.sources });
  const watch = plan.arbiterHumanSock && (plan.target === "claude" || plan.target === "codex")
    ? watchMcpConfig(input, first, plan.arbiterHumanSock, plan.scopeId, {
        call: deps.call, log: deps.watchLog ?? deps.log, registered: registration.status === "registered",
        ...(deps.intervalMs !== undefined ? { intervalMs: deps.intervalMs } : {}),
      })
    : null;
  return { registration, watch };
}
