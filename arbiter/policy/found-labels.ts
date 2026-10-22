/**
 * found-labels — the default catalog's CONTENT tier (2026-10-19,
 * docs/design/confidentiality/secret-discovery.md §2.6): a JSON, YAML, TOML
 * or (§2.9) INI-family config file the launch walk READ and found a
 * credential in is labelled `no-model`, bound nowhere, as a catalog file is.
 *
 * ── THE GAP ─────────────────────────────────────────────────────────────────
 *
 * The catalog decides by path. A password saved in `accounts/brightgrid.yaml`
 * or a platform token in a CLI's `config.json` matched no prefix and no
 * basename shape, so the file was public: the model read the password, and
 * nothing asked before it left (the `secrets-defaults` battery of 2026-10-18,
 * secret-discovery.md §2.6). The launch's policy scan (plan 14 S2) did find the
 * line and filed a suggestion, which protects nothing until a human applies
 * it. A credential in a config file is the most ordinary credential there is.
 *
 * ── THE RULE ────────────────────────────────────────────────────────────────
 *
 * The walk (secret-discovery.ts `discoverSecretsReport`) reads each CANDIDATE
 * (`contentProbeCandidate`: a `.json`, `.yaml`, `.yml` or `.toml` file, and
 * since 2026-10-19 (§2.9) an INI-family file (`.ini`, `.conf`, `.cnf`,
 * `.cfg`, `.properties`) or a credential file known by name (`.netrc`,
 * `.npmrc`, `.pypirc`, `.pgpass`, …), of at most CONTENT_PROBE_MAX_BYTES, in
 * the workspace, or directly in a tool's dot-directory in HOME (and HOME's
 * own `.pg_service.conf`); never in a test, fixture, example or
 * documentation tree, never an agent's or editor's own config: an MCP
 * config is read by its own route since 2026-10-21, `mcpConfigCandidate`
 * and `mcpConfigCredential`, §2.10) and asks
 * `credentialInDataFile`: does the extractor that builds the file's twin find
 * a span that is a credential beyond reasonable doubt? Either
 *
 *   - a value under a credential-named key (`password`, `token`, `secret`,
 *     `api_key`, `access_key`, `private_key`, `passphrase`, the launch scan's
 *     `credential-assignment` names, and a password's or a PIN's name of
 *     credential-names.ts: `pw`, `db_pw`, `SMTP_PASS`, `pin`) whose last
 *     word is no reference word (`token_url`, `secret_name`,
 *     `password_file`, `client_secret_id`), that reads as a credential
 *     (`looksLikeSecretValue`: 12+ characters, mixed, random-looking, no
 *     stand-in), is no reference (`${X}`, `{{ … }}`, `ENC[…]`, an ARN, a
 *     vault or 1Password reference), no URL, no path and holds no blank
 *     (`auth`, `_auth`: the same, for a value that reads as a token); or
 *   - under a password's or a PIN's name, a SHORT or simple value
 *     (`shortCredentialValue`, §2.9: `password = Tr0ub4`, `pin: 4821`)
 *     that is no stand-in, no public default (`postgres`, `changeit`,
 *     `hunter2`), not letters alone (a word, a mode, an identifier) and
 *     names nothing (an env variable's name, a version, a file name); or
 *   - a vendor-format credential anywhere in the file (`sk-ant-…`, `ghp_…`,
 *     `AKIA…`, a private key block: the content detector's prefix formats),
 *     as far as the twin's credential belt reaches: in a file whose keys
 *     gave the extractor a span. A vendor key alone under a name that says
 *     nothing would make the file one whole-file placeholder, which breaks
 *     its reader; that file is left to the launch scan's suggestion.
 *
 * A file found so gets a FOUND LABEL (this store). Its twin is structured by
 * construction (the deciding span is one of the extractor's), so the program
 * that parses the file still parses it, and only the values the extractor
 * masks become placeholders: the cost of a false positive is a masked value,
 * never a broken file.
 *
 * ── HOW IT COMPOSES (label-lookup.ts `composedLabel`) ───────────────────────
 *
 *   - like the CATALOG, a human label overrides it in either direction (a
 *     `public` label on the file, or on a folder above it, releases it);
 *   - it is `no-model`, bound nowhere, the strictest a machine gives: a
 *     derived label or a declared client key adds nothing over it;
 *   - a session label (no-model) is the same level.
 *
 * Machine-made and raise-only as the derived labels are, but not one of them:
 * a derived row says a process holding a secret WROTE the file, which is not
 * what happened here (`mandu why` and the dashboard say "Mandu found a
 * credential in it").
 *
 * ── LIFETIME ────────────────────────────────────────────────────────────────
 *
 * Kept in the symbol DB beside the derived labels (`found_labels`), so an
 * arbiter restart in the middle of a session keeps the file labelled, and a
 * launch in another workspace still knows it (each row is also a discovery
 * candidate of its own, as a derived path is). A row is DROPPED only when a
 * walk reads the file again and finds no credential in it (`cleared`): the
 * human removed the password, so a whole-file twin would only break the
 * file. A row whose file is gone stays (harmless; the label outlives its
 * file, as a derived one does). A file the walk could not read again (past
 * its caps) keeps its row: raise-only.
 *
 * WHO MAY ADD ONE: whoever may ask for a walk (`discoverSecrets`, the data
 * plane included). The arbiter reads the file itself; a caller can only make
 * it look. Adding a row only masks; dropping one needs a read of the file
 * that finds no credential in it.
 *
 * ── PERSONAL DOCUMENTS (2026-10-19, §2.7) ───────────────────────────────────
 *
 * The same store holds the second kind of found file: a text document the
 * walk read and found to be a statement, a payslip, a tax return, a lab
 * report, an identity document or household codes (personal-documents.ts
 * decides; rule `content:personal-document`). Its row's `kind` is
 * `document` and its `field` the document's kind; the label lookup gives it
 * the document twin's `extract` (labels kept, every value a placeholder).
 *
 * Mandu-new (no reference origin).
 */
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { homedir } from "node:os";

import Database from "../db/sqlite.js";
import { AGENTS } from "../src/generated/agents.js";
import { getSymbolDbPath } from "../symbol-table/symbol-table.js";
import { normalizeLabelPath } from "./path-labels.js";
import { CONTENT_RULE } from "./secret-catalog.js";
import { authName, fieldLastName, passwordKind, shortCredentialValue } from "./credential-names.js";
import { detectSecretShapes, looksLikeSecretValue } from "./secret-detectors.js";
import { extractSecretSpans, type SecretSpan } from "./secret-extract.js";
import { mcpConfigKind, mcpServerEntries, type McpConfigKind } from "./mcp-config.js";

export { CONTENT_RULE };

// ── Pure: which files the walk reads ────────────────────────────────────────

/** A candidate's size cap: a config file a person keeps a password in is
 *  small; a larger JSON is data (a lockfile, a dataset, a bundle). */
export const CONTENT_PROBE_MAX_BYTES = 64 * 1024;
/** How many candidates one walk reads at most, and how many bytes in all:
 *  the walk is on a launch's critical path. Past either, a candidate is not
 *  read (the report counts it, `content.capped`). */
export const CONTENT_PROBE_MAX_FILES = 1024;
export const CONTENT_PROBE_MAX_TOTAL = 8 * 1024 * 1024;

/** The extensions of the config formats the tier reads: JSON, YAML, TOML
 *  and, since 2026-10-19 (secret-discovery.md §2.9), the INI family
 *  (`config.ini`, `app.conf`, `my.cnf`, `*.cfg`, `gradle.properties`),
 *  which the extractor reads as `ini`: only the values of secret-named keys
 *  and URL passwords become placeholders, so a twin keeps the file. */
const DATA_EXT_RE = /\.(?:json|ya?ml|toml|ini|conf|cnf|cfg|properties)$/i;

/** Credential files known by name that have no such extension, each with a
 *  shape of its own in the extractor (secret-extract.ts `secretFileShape`):
 *  read wherever the tier reads (a project's `.npmrc` holding an
 *  `_authToken`, a `.pgpass` or `.netrc` copied into a workspace). In HOME
 *  the catalog's prefixes already name them (`~/.npmrc`, `~/.pgpass`, …).
 *  2026-10-19, §2.9. */
const CREDENTIAL_FILE_NAMES: ReadonlySet<string> = new Set([
  ".netrc", "_netrc", ".npmrc", ".pypirc", ".pgpass", ".boto", ".s3cfg", ".databrickscfg", ".sentryclirc",
]);

/** INI-family files read directly in HOME (the HOME tier otherwise reads
 *  only inside a tool's dot-directory), each a tool's per-user config that
 *  may hold a password or a key and that no catalog prefix names, since a
 *  whole-file twin of one without a credential would break its tool:
 *  PostgreSQL's service file (`password=`), unixODBC's user data sources
 *  (`Password=`), WakaTime's config (`api_key =`). §2.9. */
const HOME_CREDENTIAL_FILES: ReadonlySet<string> = new Set([".pg_service.conf", ".odbc.ini", ".wakatime.cfg"]);

/** Is `base` a file name the tier reads (by extension or by name)? Pure. */
function contentProbeName(base: string): boolean {
  return DATA_EXT_RE.test(base) || CREDENTIAL_FILE_NAMES.has(base);
}

/** A template by name (secret-catalog.ts TEMPLATE_NAME_RE's twin). */
const TEMPLATE_NAME_RE = /[._-](example|sample|template|dist|tmpl)([._-]|$)/i;

/** Directory names whose files are test data, examples or documentation,
 *  not a configuration anyone runs with: a recorded HTTP exchange that holds
 *  a password is the material of a task (a re-recording), and labelling it
 *  would serve the test runner a twin. The value backstop still masks a
 *  registered value met there (backstop-value-only.md). Matched on the path
 *  BELOW the walk root, so a workspace that itself lives under `~/tests/`
 *  is read. */
const NOT_CONFIG_DIRS: ReadonlySet<string> = new Set([
  "test", "tests", "__tests__", "spec", "specs", "e2e", "testing", "testdata", "test-data", "test_data",
  "fixture", "fixtures", "__fixtures__", "mock", "mocks", "__mocks__", "cassettes", "recordings",
  "snapshots", "__snapshots__", "example", "examples", "sample", "samples", "doc", "docs",
]);

/** Directories an agent or an editor keeps its OWN configuration in, whose
 *  reader is the agent's runtime (it reads the twin: a placeholder in its
 *  MCP server's environment breaks that server). Their MCP configs are read
 *  by a route of their own (`mcpConfigCandidate`, secret-discovery.md
 *  §2.10), whose launch posture leaves the agent's own readable to it. */
const AGENT_CONFIG_DIRS: ReadonlySet<string> = new Set([
  ...AGENTS.map((a) => `.${a}`), ".cursor", ".vscode", ".idea", ".zed", ".continue", ".windsurf",
]);
/** The same under `.config` (`~/.config/opencode/opencode.json`): every
 *  supported agent's (the agent registry), and the editors'. */
const AGENT_XDG_DIRS: ReadonlySet<string> = new Set([...AGENTS, "zed", "Code", "Cursor", "VSCodium"]);
/** Agent and editor config files by name, wherever they lie. */
const AGENT_CONFIG_FILES: ReadonlySet<string> = new Set([
  ".mcp.json", "mcp.json", "claude_desktop_config.json", "opencode.json", "opencode.jsonc", ".claude.json",
]);

/** Manifests and lockfiles: never a credential store, and the most numerous
 *  JSON, YAML and TOML files in a project (not read, so not paid for). */
const MANIFEST_RE = /^(?:setup\.cfg|tox\.ini|pytest\.ini|mypy\.ini|\.bumpversion\.cfg|gradle-wrapper\.properties|package(?:-lock)?\.json|npm-shrinkwrap\.json|composer\.(?:json|lock)|(?:ts|js)config(?:\..+)?\.json|deno\.json|Cargo\.toml|pyproject\.toml|pnpm-lock\.yaml|pnpm-workspace\.yaml|\.?eslintrc\.json|\.prettierrc\.json|renovate\.json|turbo\.json|nx\.json|lerna\.json|angular\.json|project\.json|\.pre-commit-config\.yaml|codecov\.yml|mkdocs\.yml)$/;

/** Where a walk stands: in a workspace root (every candidate below it), or
 *  in HOME (only a tool's own dot-directory: `~/.railway/config.json`,
 *  `~/.config/turso/settings.json`; HOME's projects are read when a launch
 *  names them as its workspace). */
export type ProbeTier = "workspace" | "home";

/**
 * Does the walk read this file for the content tier? `rel`: the path's
 * segments below its walk root (the basename last). Pure.
 */
export function contentProbeCandidate(rel: readonly string[], tier: ProbeTier): boolean {
  if (rel.length === 0) return false;
  const base = rel[rel.length - 1]!;
  if (!contentProbeName(base) && !(tier === "home" && rel.length === 1 && HOME_CREDENTIAL_FILES.has(base))) return false;
  if (TEMPLATE_NAME_RE.test(base) || MANIFEST_RE.test(base) || AGENT_CONFIG_FILES.has(base)) return false;
  const dirs = rel.slice(0, -1);
  for (let i = 0; i < dirs.length; i++) {
    const d = dirs[i]!;
    if (NOT_CONFIG_DIRS.has(d.toLowerCase()) || AGENT_CONFIG_DIRS.has(d)) return false;
    if (d === ".config" && i + 1 < dirs.length && AGENT_XDG_DIRS.has(dirs[i + 1]!)) return false;
  }
  if (tier === "home") return (dirs.length === 0 && HOME_CREDENTIAL_FILES.has(base)) || (dirs.length >= 1 && dirs.length <= 2 && dirs[0]!.length > 1 && dirs[0]!.startsWith("."));
  return true;
}

// ── Pure: is it a credential? ───────────────────────────────────────────────

/** The names the launch scan's `credential-assignment` detector reads as a
 *  credential's (secret-detectors.ts), and `credential`. */
const CREDENTIAL_NAME_RE = /(?:secret|token|passw(?:or)?d|passphrase|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|credential)/i;

/** A name's last word that makes it the name of something ABOUT a
 *  credential, not the credential (`token_url`, `secretName`,
 *  `password_file`, `api_key_id`, `secretKeyRef`). */
const REFERENCE_WORDS: ReadonlySet<string> = new Set([
  "url", "uri", "endpoint", "host", "path", "file", "dir", "name", "id", "type", "ref", "env", "var", "policy",
  "hint", "label", "length", "len", "ttl", "expiry", "expires", "expiration", "header", "prefix", "field", "arn",
  "version", "format", "mode", "hash", "sha", "sha1", "sha256", "digest", "checksum", "fingerprint", "count",
  "limit", "template", "location", "source", "provider", "kind", "store", "class", "size", "timeout", "enabled",
  "required", "rotation", "date", "time", "issuer", "audience", "algorithm", "method", "command", "cmd", "helper",
  "index", "regex", "pattern",
]);

/** The words of a key name: split at `_`, `-`, `.`, blanks and camelCase. */
function words(name: string): string[] {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").split(/[\s_.\-]+/).filter(Boolean).map((w) => w.toLowerCase());
}

/** Is `name` (one key, not a dotted path) a credential's name? The
 *  `credential-assignment` names, and since 2026-10-19 (§2.9) every name
 *  credential-names.ts reads as a password's or a PIN's (`pw`, `db_pw`,
 *  `PGPASSWORD`, `SMTP_PASS`, `passcode`, `card_pin`, `access_code`).
 *  `auth` is not one here: it names a mode as often (`auth: basic`), and
 *  `spanIsCredential` takes it for a token-like value only. Pure. */
export function credentialName(name: string): boolean {
  if (passwordKind(name) !== null) return true;
  if (!CREDENTIAL_NAME_RE.test(name)) return false;
  const w = words(name);
  const last = w[w.length - 1];
  // `adminPasswordKey`, `tokenKey`: the name of the key a password or a
  // token is kept under (a Helm chart's `secretKeys`), not one. `api_key`,
  // `secret_key`, `private_key` are credentials.
  if (last === "key" && w.length >= 2 && /^(?:password|passwd|pwd|token|credentials?)$/.test(w[w.length - 2]!)) return false;
  return last !== undefined && !REFERENCE_WORDS.has(last);
}

/** A value that NAMES where a credential is rather than being one: a
 *  template or reference syntax `looksLikeSecretValue` does not already
 *  refuse, a URL with no password in it, a file path, prose. Pure. */
export function referenceValue(v: string): boolean {
  if (/\s/.test(v)) return true;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return true;
  if (/^(?:\/|\.\.?\/|~\/|[A-Za-z]:[\\/])/.test(v)) return true;
  return /^(?:ENC\[|arn:|op:\/\/|vault:|ref\+|sm:\/\/|secretsmanager:|projects\/[^/]+\/secrets\/|!)/i.test(v);
}

/** The prefix formats of the content detector (a vendor key, a private key
 *  block): evidence by themselves, under any key. Pure. */
function vendorCredential(v: string): boolean {
  return detectSecretShapes(v, { maxHits: 4 }).some((h) => h.shape !== "credential-assignment" && h.shape !== "url-password");
}

/** The last key name of a span's field (credential-names.ts). */
const lastName = fieldLastName;

/** A value of lowercase words and digits joined by `-`, `_` or `.`
 *  (`oauth2-client-credentials`): under `auth` a mode or a scheme's name,
 *  not a token. */
const LOWER_WORDS_RE = /^[a-z0-9]+(?:[-_.][a-z0-9]+)+$/;

/** One span: is it a credential beyond reasonable doubt? Pure. */
function spanIsCredential(s: SecretSpan): boolean {
  if (vendorCredential(s.value)) return true;
  // A commented-out line's token is evidence only in a vendor format.
  if (s.comment) return false;
  if (referenceValue(s.value)) return false;
  // A URL's password is the field `<key>.password` (the extractor's own).
  const name = lastName(s.key);
  if (looksLikeSecretValue(s.value)) {
    if (credentialName(name)) return true;
    // `auth` (`_auth` in an `.npmrc`, `"auth"` in a registry login): a
    // token-like value only (§2.9).
    return authName(name) && !LOWER_WORDS_RE.test(s.value);
  }
  // THE SHORT-VALUE RULE (2026-10-19, §2.9): under a password's or a PIN's
  // name, a value too short or too simple for `looksLikeSecretValue`
  // (`password = Tr0ub4`, `db_pw: k9z!q2`, `pin: 4821`) that is no stand-in,
  // no public default (`postgres`, `hunter2`), no word and names nothing.
  const kind = passwordKind(name);
  return kind !== null && shortCredentialValue(s.value, kind);
}

/**
 * Is `text`, the content of the config file at `path`, a file the content
 * tier labels? The FIELD of the first span that decides it (for the audit,
 * never a value), or null. Every span the extractor finds is still masked in
 * the twin; this only decides whether the file is labelled. Pure.
 */
export function credentialInDataFile(path: string, text: string): string | null {
  const base = path.slice(path.lastIndexOf("/") + 1);
  if (!contentProbeName(base) && !HOME_CREDENTIAL_FILES.has(base)) return null;
  const x = extractSecretSpans(path, text);
  if (x.shape === null || x.spans.length === 0) return null;
  for (const s of x.spans) {
    if (spanIsCredential(s)) return s.key;
    for (const p of s.parts ?? []) if (spanIsCredential(p)) return p.key;
  }
  return null;
}

// ── Pure: MCP and editor configs (secret-discovery.md §2.10) ────────────────

/** An MCP config's size cap: Claude Code's `.claude.json` is its whole
 *  state file (every project's settings), larger than a config a person
 *  writes by hand. Past it the file is not read (the walk names it). */
export const MCP_CONFIG_PROBE_MAX_BYTES = 2 * 1024 * 1024;

/** The MCP config kinds a WORKSPACE walk reads where it meets them: a
 *  project's own (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`). The
 *  per-user files are read at their places in HOME (`mcpHomeConfigPaths`,
 *  the walk's MCP pass), wherever a prune would have kept them out. */
const WORKSPACE_MCP_KINDS: ReadonlySet<McpConfigKind> = new Set<McpConfigKind>(["claude-project", "cursor", "vscode"]);

/**
 * Does the walk read this file as an MCP config (`rel`: its segments below
 * the walk root)? In a workspace, a project's MCP config anywhere but in a
 * test, fixture, example or documentation tree; in HOME, one of the
 * per-user files at its place (`~/.cursor/mcp.json`, the Claude Desktop and
 * Windsurf configs, VS Code's user file). Never `.claude.json` or Codex's
 * `config.toml` here: they are an agent's login or store, which the walk
 * judges per launch (its MCP pass). Pure.
 */
export function mcpConfigCandidate(rel: readonly string[], tier: ProbeTier): boolean {
  if (rel.length === 0) return false;
  const kind = mcpConfigKind(rel.join("/"));
  if (kind === null || kind === "claude" || kind === "codex") return false;
  if (tier === "workspace") {
    if (!WORKSPACE_MCP_KINDS.has(kind)) return false;
    return !rel.slice(0, -1).some((d) => NOT_CONFIG_DIRS.has(d.toLowerCase()));
  }
  return kind !== "claude-project";
}

/** A value's words that could be a token: split at blanks, quotes, braces,
 *  `:`, `,`, `=` and a backslash (a JSON header set inside an `env` value,
 *  `{"Authorization": "Bearer ntn_…"}`). */
function tokenWords(v: string): string[] {
  return v.split(/[\s"'{}:,=\\]+/).filter((w) => w.length > 0);
}

/**
 * Is `text`, the content of the MCP config at `path`, one the catalog
 * labels (secret-discovery.md §2.10)? The field of the first server value
 * that decides it (`<server>.<field>`, for the audit, never a value), or
 * null. Decided on the twin's own spans (secret-extract.ts: the key rules,
 * the list rules, the credential belt and `mcpEntrySpans`) that lie inside
 * a server entry: one is a credential when the content tier would take it
 * (`spanIsCredential`), when it is a vendor format, or when one of its
 * words reads as a token (`looksLikeSecretValue`: `Bearer <token>`, an API
 * key under a name that says nothing, a header set in a variable). A
 * reference the client expands (`${GITHUB_TOKEN}`) never is, so a config
 * that only names its variables stays public and every program reads it as
 * written. Pure.
 */
export function mcpConfigCredential(path: string, text: string): string | null {
  const entries = mcpServerEntries(path, text);
  if (entries === null || entries.length === 0) return null;
  const x = extractSecretSpans(path, text);
  if (x.shape === null || x.spans.length === 0) return null;
  for (const s of x.spans) {
    for (const p of [s, ...(s.parts ?? [])]) {
      const e = entries.find((en) => p.start >= en.start && p.end <= en.end);
      if (e === undefined || /\$\{[^}]*\}/.test(p.value)) continue;
      if (spanIsCredential(p) || vendorCredential(p.value) || tokenWords(p.value).some((w) => looksLikeSecretValue(w) && !referenceValue(w))) return `${e.name}.${p.key}`;
    }
  }
  return null;
}

// ── I/O: read one candidate ─────────────────────────────────────────────────

/**
 * The text of a candidate, or null: not a regular file (decided on `lstat`
 * and again on the descriptor, so a FIFO is never waited on and a symlink
 * never followed), larger than `max`, unreadable, or not UTF-8 text.
 */
export function readCandidate(p: string, max: number = CONTENT_PROBE_MAX_BYTES): string | null {
  let fd: number | null = null;
  try {
    const st = lstatSync(p, { throwIfNoEntry: false });
    if (!st || !st.isFile() || st.size > max || st.size === 0) return null;
    fd = openSync(p, constants.O_RDONLY | constants.O_NONBLOCK | (constants.O_NOFOLLOW ?? 0));
    const fst = fstatSync(fd);
    if (!fst.isFile() || fst.size > max) return null;
    const buf = Buffer.alloc(Math.min(fst.size, max));
    const n = readSync(fd, buf, 0, buf.length, 0);
    const text = buf.subarray(0, n).toString("utf8");
    return text.includes("\u0000") || text.includes("�") ? null : text;
  } catch {
    return null;
  } finally {
    if (fd !== null) try { closeSync(fd); } catch { /* closed */ }
  }
}

// ── The store ───────────────────────────────────────────────────────────────

/** What the content tier found in a file: a credential in a config file
 *  (§2.6), or a personal document (personal-documents.ts, §2.7). */
export type FoundKind = "credential" | "document";

/** One file the content tier labelled. */
export interface FoundLabel {
  /** Absolute, normalized (HumanView spelling). */
  path: string;
  /** What decided it, never a value: for a credential the field whose
   *  value it is (`password`, `staging.token`), for a document its kind
   *  (`bank-statement`, personal-documents.ts DocumentKind). What `mandu
   *  why` names. */
  field: string;
  /** Absent: a credential (a row of the first content tier). A `document`
   *  is registered with the document twin (personal-documents.ts
   *  DOCUMENT_TWIN_EXTRACT). */
  kind?: "document";
  foundAt: number;
  updatedAt: number;
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS found_labels (
  path       TEXT PRIMARY KEY,
  field      TEXT    NOT NULL DEFAULT '',
  found_at   INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  kind       TEXT    NOT NULL DEFAULT 'credential'
);
`;

/** A bound on the rows kept: past it a new file is not labelled (the walk
 *  still lists it for this launch, which registers and twins it). */
export const FOUND_LABELS_MAX = 100_000;

export interface FoundLabelStoreOptions {
  dbPath?: string;
}

/**
 * The found labels: an in-memory map (the label lookup runs on every
 * classify) written through to SQLite, hydrated at construction, as
 * DerivedLabelStore is. `generation` changes with every add or drop (the
 * guard's roots are keyed on it).
 */
export class FoundLabelStore {
  private readonly db: InstanceType<typeof Database>;
  private readonly rows = new Map<string, FoundLabel>();
  private gen = 0;

  constructor(opts: FoundLabelStoreOptions = {}) {
    this.db = new Database(opts.dbPath ?? getSymbolDbPath());
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA_SQL);
    // A table of the first content tier (2026-10-19) has no `kind`: every
    // row of it is a credential's.
    const cols = this.db.prepare("PRAGMA table_info(found_labels)").all() as Array<{ name: string }>;
    if (!cols.some((c) => c.name === "kind")) this.db.exec("ALTER TABLE found_labels ADD COLUMN kind TEXT NOT NULL DEFAULT 'credential'");
    const rows = this.db.prepare("SELECT path, field, found_at, updated_at, kind FROM found_labels").all() as Array<{ path: string; field: string; found_at: number; updated_at: number; kind: string }>;
    for (const r of rows) {
      this.rows.set(r.path, { path: r.path, field: r.field ?? "", ...(r.kind === "document" ? { kind: "document" as const } : {}), foundAt: r.found_at, updatedAt: r.updated_at });
    }
  }

  /** Label `rawPath` (absolute). Null: not an absolute path, or the store
   *  is full. An existing row keeps its first time and takes the new field
   *  and kind. */
  add(rawPath: string, field: string, home: string = homedir(), kind: FoundKind = "credential"): FoundLabel | null {
    const p = normalizeLabelPath(rawPath, home);
    if (p === null) return null;
    const prev = this.rows.get(p);
    if (prev === undefined && this.rows.size >= FOUND_LABELS_MAX) return null;
    if (prev !== undefined && prev.field === field && (prev.kind ?? "credential") === kind) return prev;
    const now = Date.now();
    const row: FoundLabel = { path: p, field: String(field).slice(0, 200), ...(kind === "document" ? { kind } : {}), foundAt: prev?.foundAt ?? now, updatedAt: now };
    this.db.prepare(
      `INSERT INTO found_labels (path, field, found_at, updated_at, kind) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(path) DO UPDATE SET field = excluded.field, updated_at = excluded.updated_at, kind = excluded.kind`,
    ).run(row.path, row.field, row.foundAt, row.updatedAt, kind);
    this.rows.set(p, row);
    this.gen++;
    return row;
  }

  /** Drop the row of a file a walk read and found no credential in. */
  drop(rawPath: string, home: string = homedir()): boolean {
    const p = normalizeLabelPath(rawPath, home);
    if (p === null || !this.rows.has(p)) return false;
    this.rows.delete(p);
    this.db.prepare("DELETE FROM found_labels WHERE path = ?").run(p);
    this.gen++;
    return true;
  }

  generation(): number {
    return this.gen;
  }

  /** The live map, for the pure resolver. */
  map(): ReadonlyMap<string, FoundLabel> {
    return this.rows;
  }

  close(): void {
    try { this.db.close(); } catch { /* double-close must not throw */ }
  }
}
