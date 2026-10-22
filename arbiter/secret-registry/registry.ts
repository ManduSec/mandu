/**
 * secret-registry — pre-symbolize the user's secrets so the agent learns
 * NAMES, never BYTES (docs/design/confidentiality/confidentiality.md §7.2/§7.3; plan 4′).
 *
 * WHY THE ARBITER READS THE FILE: the arbiter is the one component that runs
 * OUTSIDE the agent's sandbox. Registering by PATH (not by value) means the
 * secret bytes cross exactly one boundary — disk → arbiter — and never enter
 * the launcher process, the IPC request, or any agent-reachable world. The
 * launcher receives only the symbol, which is what it writes into the twin.
 *
 * The registered symbol is `no-model` × `trusted` integrity: these are the
 * user's OWN files, not attacker-controlled input, which is exactly what lets
 * the egress gate release them at a BOUND destination with no approval
 * (confidentiality.md §3.2). A secret that arrives from an untrusted source
 * still registers untrusted through the normal ingress path.
 *
 * Registration is idempotent by the symbol table's existing reuse key
 * (tool+field+origin+session+callId+value), so re-registering the same
 * unchanged file returns the same symbol — the twin stays stable across
 * launches and the model's references keep resolving.
 *
 * Mandu-new (no reference origin).
 */
import { readFileSync, realpathSync, statSync } from "fs";
import { homedir } from "os";
import { basename, join, resolve } from "path";
import type { SymbolEntry, SymbolMap } from "../symbol-table/symbol-table.js";
import {
  allocateSymbol,
  findReusableSymbol,
  findSymbolsByValue,
  persistSymbol,
  recordWireGrant,
  touchSymbolMap,
} from "../symbol-table/symbol-table.js";
import { pathConfidentiality, type LabelLookup, type SecretCatalogMatch } from "../policy/secret-catalog.js";
import { agentLoginConfidentiality, loginOwnerOf } from "../policy/secret-discovery.js";
import { mcpConfigKind } from "../policy/mcp-config.js";
import { syncRegisteredBindings } from "./current-bindings.js";
import { isSecret, maxConfidentiality, type ConfidentialityLevel } from "../symbol-table/confidentiality.js";
import { getActiveFormat } from "../symbol-table/symbol-format.js";
import { valueFingerprints } from "../policy/egress-fingerprint.js";
import { DOCUMENT_TWIN_EXTRACT } from "../policy/personal-documents.js";
import { documentFileText, documentFormatOf } from "../policy/document-text.js";
import { renderTwinPdf } from "../policy/document-twin-pdf.js";
import {
  extractSecretSpans,
  envSecretSpan,
  npmrcProxyBypassKeys,
  type EnvSecretRules,
  renderStructuredTwin,
  secretFileShape,
  shapeIsExhaustive,
  type SecretExtraction,
  type SecretSpan,
} from "../policy/secret-extract.js";

/** The tool tag registered secrets are minted under. "Read" so the symbol reads
 *  exactly like the file read it stands in for ($MDU:nomodel_Read[…]), and the
 *  origin column carries the path. */
const REGISTRY_TOOL = "Read";

/** Was this row registered from a labelled FILE by {@link registerSecret}
 *  (the file's base row or one of its fields), not minted from a tool
 *  result? The registry's rows are the only `Read` rows with no call id, an
 *  origin path and trusted integrity; a proxy's `Read` result carries its
 *  call id. Plan 10 §11.15: only such a row gives its bare tokens. Pure. */
export function isRegisteredFileRow(e: Pick<SymbolEntry, "tool" | "call_id" | "origin" | "integrity">): boolean {
  return e.tool === REGISTRY_TOOL && e.call_id === null && e.origin !== null && e.integrity === "trusted";
}
/** The tool tag for a masked environment variable ($MDU:nomodel_Env[…].NAME). */
const ENV_TOOL = "Env";

/** The variable a masked environment variable's row stands for
 *  (`registerEnvSecret`: tool `Env`, origin `env:NAME`, trusted), else null.
 *  Pure. */
export function envRowVariable(e: Pick<SymbolEntry, "tool" | "origin" | "integrity">): string | null {
  if (e.tool !== ENV_TOOL || e.integrity !== "trusted" || typeof e.origin !== "string" || !e.origin.startsWith("env:")) return null;
  const name = e.origin.slice(4);
  return name === "" ? null : name;
}

export interface RegisterSecretResult {
  /** The symbol standing for this file's contents; null when the path is not a
   *  catalog secret, is unreadable, or the axis is off. NEVER throws. */
  symbol: string | null;
  /** Why, for the audit trail. */
  reason: string;
  /** The STRUCTURED twin (plan 10 §2.4): the file's own text with each secret
   *  value replaced by its field symbol (`KEY=$MDU:nomodel_Read[h].KEY`). Absent
   *  when the file has no known shape: the launcher then writes the
   *  whole-file twin (the symbol alone), exactly as before. For an
   *  EXHAUSTIVE shape with no secret value (secret-extract.ts
   *  `shapeIsExhaustive`: an `~/.ssh/config`, a `pip.conf` with no
   *  credential) it is the file's own text and `fields` is 0. */
  twin?: string;
  /** Which shape produced the twin (`dotenv`, `ini`, …). */
  shape?: string;
  /** Whole-file twin only (no `twin`): the original's final line terminator
   *  (`"\n"`, `"\r\n"`, or `""` for a file that ends without one), so the
   *  launcher's `<symbol><terminator>` ends as the file does. One bit of the
   *  file's shape, never its length (2026-10-02: the twin always ended in
   *  `\n`, and Codex quoted the extra byte as a blank row). Absent from an
   *  older arbiter: the launcher writes `\n`. */
  terminator?: "" | "\n" | "\r\n";
  /** The file's reader list as the law has it (plan 10 §2.1): how many
   *  programs are named and how many of those are PINNED by hash (§11.2).
   *  Absent when the label carries no list (structured twin for every
   *  program). The launch mode line counts the pins (§12.5). */
  readers?: { named: number; pinned: number };
  /** How many secret values got their own field symbol. */
  fields?: number;
}

export interface RegisterEnvSecretResult {
  /** `$MDU:nomodel_Env[h].NAME`; null when the variable is not a secret. */
  symbol: string | null;
  reason: string;
  /** The value the agent's environment gets: the symbol, or for a URL with a
   *  password the URL with only the password replaced. */
  twin?: string;
  /** The host the value itself names as the secret's wire (plan 10
   *  §11.13.1: a pip index URL's password, bound to that index). The row
   *  keeps no URL, so the caller remembers it to re-derive the row's
   *  bindings under a changed law (current-bindings.ts). */
  wireHost?: string;
}

export interface SecretRegistryEntry {
  path: string;
  symbol: string;
  /** Field symbols minted for the file's secret values (0 = whole-file twin). */
  fields: number;
  /** Bound destinations this datum may be released to (confidentiality.md §2).
   *  Empty = none. §6 REQUIRES this be visible: each binding is a STANDING
   *  release rule, so the human must be able to see the whole surface. */
  bindings: string[];
  /** The level, so the dashboard can distinguish strict from model-ok. */
  level: string;
}

/**
 * Is `value`, the current text of `path`, already registered as that file at
 * a level at least `level`? An active base row of the registry (no field, no
 * call id, trusted) of that origin and that exact text, under ANY session
 * key. Plan 10 §11.15 case 2: the arbiter's own registration of a file read
 * raw (`server.ts` `registerReadFile`) is for a file the launch never
 * registered; one the launch registered (with or without a session key) is
 * a known secret already, and a second base row under another allocation key
 * (no session, no launch HOME, so no wire binding) would compete with it for
 * "the file's newest registration" (`wireServableTwin`, `structuredTwinFor`,
 * whose `created_at` is in whole seconds: the winner depended on whether the
 * two registrations fell in the same second). Pure over the symbol table.
 */
export function fileRegisteredAsIs(symbolMap: SymbolMap, path: string, value: string, level: ConfidentialityLevel): boolean {
  for (const e of symbolMap.symbols.values()) {
    if (e.obsoleted_at !== null || e.field !== null || !isRegisteredFileRow(e)) continue;
    if (e.origin !== path || e.value !== value || !isSecret(e.confidentiality)) continue;
    if (maxConfidentiality(e.confidentiality, level) === e.confidentiality) return true;
  }
  return false;
}

/**
 * Read a secret file and mint (or reuse) its symbol. Fail-soft by contract:
 * every failure returns `{symbol: null}` with a reason — a launcher that cannot
 * twin one file must still be able to decide what to do, and an exception here
 * would take down the arbiter's dispatch.
 */
export function registerSecret(
  symbolMap: SymbolMap,
  args: {
    path: string; home?: string; sessionKey?: string; resolveLabel?: LabelLookup;
    /** The launches' auth grants (auth-grants.ts, agent-sign-in.md §3):
     *  the bindings law keeps a granted field bound to those hosts. */
    fieldGrants?: (origin: string, field: string) => readonly string[];
    /** The launch's values of the variables that move an agent's login
     *  file (secret-discovery.ts LOGIN_ENV, `pickLoginEnv`d by the server):
     *  a login moved out of the catalog's places is judged as the walk
     *  judged it (`agentLoginConfidentiality`, secret-discovery.md §1.10). */
    loginEnv?: Readonly<Record<string, string>>;
    /** May this registration give the launch HOME's `.npmrc` / pip.conf
     *  fields their wire grant (plan 10 §11.13.1)? False for a caller that
     *  is not trusted to say which directory is the launch HOME: the server
     *  passes false for a request on the data socket, which the agent's
     *  world can reach, so a `home` of its choosing earns nothing
     *  (confidentiality.md §2.1, 2026-10-17). Default true. */
    wireGrant?: boolean;
  },
  dbPath?: string,
): RegisterSecretResult {
  // The USER label wins over the catalog (Plan 6, §6), so this registers a
  // human-labeled secret — at EITHER level — and refuses a path the human
  // explicitly declassified to `public`, even one the catalog would match.
  // Without this, a user-labeled secret would be protected at the model
  // boundary (the proxy symbolizes it) but NOT byte-confined (no twin) — an
  // asymmetry with catalog secrets that nobody would expect.
  // An agent's login file the catalog does not name (CODEX_HOME moved it)
  // is `no-model` unless a label says otherwise, as the walk found it.
  const owner = args.loginEnv !== undefined ? loginOwnerOf(args.path, args.home ?? homedir(), args.loginEnv) : null;
  const catalog = pathConfidentiality(args.path, args.home, args.resolveLabel);
  const match = owner !== null ? agentLoginConfidentiality(catalog, owner) : catalog;
  if (match.rule === null || !isSecret(match.level)) {
    return { symbol: null, reason: `not a secret path (catalog or label): ${args.path}` };
  }

  let value: string;
  // A PDF or Office document under an `extract:` (a personal document the
  // content tier found, or a human's label with one): the row's value is
  // the document's TEXT (secret-discovery.md §2.8), what the twin, the
  // field rows and the value backstop are made from. One it cannot read
  // falls back to its bytes, whose extraction finds nothing: the
  // whole-file twin, one placeholder (fail closed).
  const docText = match.extract !== undefined ? registeredDocumentText(args.path) : null;
  try {
    value = docText ?? readFileSync(args.path, "utf8");
  } catch (err) {
    return { symbol: null, reason: `unreadable: ${(err as Error).message}` };
  }
  if (value === "") {
    return { symbol: null, reason: "empty file — nothing to symbolize" };
  }

  // Plan 13 D4, a holder's working-directory file (2026-10-04): a DERIVED
  // file whose whole text is the canonical absolute path of a directory that
  // exists (what `pwd -P` writes: Claude Code's `/tmp/claude-<n>-cwd`, which
  // the call's shell writes after its command, a holder once it reaped the
  // reader) carries nothing but a NAME present in the filesystem, the
  // channel §4.9 leaves uncovered (a holder's directory names are listed by
  // any later call). Its twin is its own text, and no symbol is minted, so
  // the path is no registered value either. Only under a derived label: a
  // human's label or the catalog says the file itself is the secret.
  if (match.rule.startsWith("derived:")) {
    const dir = directoryLineOf(value);
    if (dir !== null && isCanonicalDirectory(dir)) {
      return { symbol: null, reason: "a derived file holding only the name of an existing directory: the twin is its own text (plan 13 D4, §4.9 names)", twin: value, shape: "directory-path" };
    }
  }

  const key = {
    tool: REGISTRY_TOOL,
    value,
    origin: args.path,
    sessionKey: args.sessionKey,
    confidentiality: match.level,
    bindings: match.bindings.length > 0 ? match.bindings : undefined,
    integrity: "trusted" as const,
  };

  // The label law in force governs the file's rows, not the law at their
  // first mint (current-bindings.ts, confidentiality.md §2.1): a binding
  // added or removed since then applies to the rows reused below.
  const syncOpts = { resolveLabel: args.resolveLabel, paths: [args.path], ...(args.fieldGrants ? { fieldGrants: args.fieldGrants } : {}) };
  syncRegisteredBindings(symbolMap, syncOpts, dbPath);
  const reused = findReusableSymbol(symbolMap, key);
  const symbol = reused ?? allocateSymbol(symbolMap, key, dbPath);
  const how = reused !== null ? `already registered (${match.rule})` : `registered (${match.rule})`;
  const readers = readerCounts(args.resolveLabel?.(args.path)?.readers);

  // The structured twin (plan 10 §2.4): one FIELD symbol per secret value,
  // sharing the base symbol's hash so the names read as fields of the file
  // (`$MDU:nomodel_Read[9bbd].STRIPE_KEY`). Each field row carries the value it
  // stands for, so the egress gate releases exactly that value at the file's
  // bound destinations and the fingerprint scan holds it. Reuse is per field,
  // by the same allocation key, so an unchanged file yields the same names.
  //
  // An EXHAUSTIVE shape with no secret value (an `~/.ssh/config`, a `pip.conf`
  // with no credential) twins as its own text, but only on the CATALOG's
  // word: a human label (or a derived one: a high session wrote the file)
  // says the file itself is the secret, so it keeps the whole-file twin.
  const byCatalog = byCatalogRule(match.rule);
  // Plan 10 §11.13.1: the launch HOME's `.npmrc` and pip.conf only (never a
  // workspace one, which the agent can write), read here from the real file:
  // each value npm or pip sends to the registry or index its own key or URL
  // names is bound to that host.
  const wireHosts = args.wireGrant !== false && isHomeWireFile(args.path, args.home);
  const structured = mintFields(symbolMap, symbol, value, args, key, dbPath, match.extract, byCatalog, wireHosts);
  // A field minted just now carries the whole file's bindings only: an auth
  // grant for it, and its own value's bindings under `values:` (plan 13
  // §5.2), apply from its first registration, not the next sync.
  if ((args.fieldGrants || match.values) && structured !== null && structured.spans.length > 0) syncRegisteredBindings(symbolMap, syncOpts, dbPath);
  if (structured === null) return { symbol, reason: how, terminator: finalTerminator(value), ...(readers ? { readers } : {}) };
  // A PDF's twin is still a PDF (document-twin-pdf.ts): the twin's text set
  // as one, so a reader of PDFs reads the placeholders. An Office
  // document's twin is the text itself (§2.8).
  const asPdf = docText !== null && documentFormatOf(args.path) === "pdf";
  return {
    symbol,
    reason: structured.spans.length === 0
      ? `${how}; ${structured.shape} holds no secret value: the twin is the file's own text`
      : `${how}; structured twin: ${structured.shape}, ${structured.spans.length} field(s)${docText !== null ? `, of the document's text${asPdf ? ", as a PDF" : ""}` : ""}`,
    twin: asPdf ? renderTwinPdf(structured.twin) : structured.twin,
    shape: structured.shape,
    fields: structured.spans.length,
    ...(readers ? { readers } : {}),
  };
}

/**
 * The text a PDF or Office document at `path` is registered by
 * (secret-discovery.md §2.8): its extracted text (document-text.ts), or
 * null for a path of another format or a document it cannot read. Only
 * under an `extract:` (`registerSecret`, the server's raw-read
 * registration): a document labelled with none is registered by its bytes,
 * the whole-file twin, as before.
 */
export function registeredDocumentText(path: string): string | null {
  return documentFormatOf(path) === null ? null : documentFileText(path);
}

/**
 * The registered PDF document at `path`, for the model proxy's document
 * block (document-blocks.ts, secret-discovery.md §2.8): its twin's text (the
 * twin PDF's text, `registerSecret` renders it) and the text it was
 * registered by. Null unless `path` is a `.pdf` whose newest registry base
 * row (`isRegisteredFileRow`, no field, a secret level) renders a structured
 * twin under the law in force. Pure over the symbol table and the label
 * lookup.
 */
export function registeredDocumentTwin(
  symbolMap: SymbolMap,
  path: string,
  opts: { resolveLabel?: LabelLookup } = {},
): { path: string; text: string; base: string } | null {
  if (documentFormatOf(path) !== "pdf") return null;
  let base: { name: string; value: string; created: number } | null = null;
  for (const [name, e] of symbolMap.symbols) {
    if (e.obsoleted_at !== null || e.field !== null || !isRegisteredFileRow(e)) continue;
    if (e.origin !== path || !isSecret(e.confidentiality)) continue;
    if (base === null || e.created_at > base.created) base = { name, value: e.value, created: e.created_at };
  }
  if (base === null) return null;
  const twin = renderRegisteredTwin(symbolMap, path, base.name, base.value, opts);
  return twin === null ? null : { path, text: twin.text, base: base.value };
}

/** The reader list's shape for the registration result: named programs and
 *  the pinned subset (an entry with a sha256). Undefined for no list. */
function readerCounts(
  readers: ReadonlyArray<string | { app: string; path?: string; sha256?: string }> | undefined,
): { named: number; pinned: number } | undefined {
  if (!Array.isArray(readers)) return undefined;
  let pinned = 0;
  for (const r of readers) if (typeof r !== "string" && typeof r.sha256 === "string" && r.sha256 !== "") pinned++;
  return { named: readers.length, pinned };
}

/** The path a file's text names when the text is ONE absolute path and at
 *  most one final `\n`: no other line, no control character, no `.` or `..`
 *  segment, no empty segment or trailing slash (`/` alone excepted), at most
 *  `PATH_MAX` (4096) bytes. Null otherwise. Pure. */
export function directoryLineOf(text: string): string | null {
  const p = text.endsWith("\n") ? text.slice(0, -1) : text;
  if (p.length === 0 || Buffer.byteLength(p) > 4096 || !p.startsWith("/")) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(p)) return null;
  if (p === "/") return p;
  const segs = p.slice(1).split("/");
  if (segs.some((s) => s === "" || s === "." || s === "..")) return null;
  return p;
}

/** Is `p` an existing directory named canonically (its own real path, so no
 *  symlink anywhere on it)? */
function isCanonicalDirectory(p: string): boolean {
  try {
    return realpathSync(p) === p && statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** A file's final line terminator, for the whole-file twin (`terminator`). */
export function finalTerminator(content: string): "" | "\n" | "\r\n" {
  return content.endsWith("\r\n") ? "\r\n" : content.endsWith("\n") ? "\n" : "";
}

/** Does the CATALOG decide this rule (not a human's or a derived label)?
 *  Only the catalog's word lets an exhaustive shape with no secret value
 *  twin as its own text. */
function byCatalogRule(rule: string | null): boolean {
  return rule !== null && (rule.startsWith("prefix:") || rule.startsWith("shape:"));
}

/** Which twin an extraction makes: `whole-file` when the file has no
 *  readable shape, or its shape found no secret value and is not exhaustive
 *  (or `exhaustiveOk` is off: a human or derived label says the file itself
 *  is the secret); `own-text` for an exhaustive shape with no secret value;
 *  else `structured`. `mintFields` and `twinFormOf` both decide by it. Pure. */
function twinDecision(x: SecretExtraction, exhaustiveOk: boolean): TwinForm["form"] {
  if (x.shape === null) return "whole-file";
  if (x.spans.length > 0) return "structured";
  return exhaustiveOk && shapeIsExhaustive(x.shape) ? "own-text" : "whole-file";
}

/** What programs that read a registered file get in its place (plan 10
 *  §2.4): `structured`, the file's own text with each of `fields` secret
 *  values a placeholder; `own-text`, the file as it is (an exhaustive shape
 *  holding no secret, on the catalog's word, or a derived file naming a
 *  directory); `whole-file`, one placeholder for the whole file (`shape`
 *  then says which shape found no secret value, or null when the file has
 *  none Mandu can read in place: no known shape, or a TOML inline table). */
export interface TwinForm {
  form: "structured" | "own-text" | "whole-file";
  shape: string | null;
  fields: number;
}

/**
 * The twin `registerSecret` makes of a file whose text is `value`, matched
 * by `match`, decided the same way but minting nothing. `mandu why` reports
 * it (2026-10-09): it used to infer a structure-keeping twin from the path
 * alone, so it said "each value is a placeholder" of a `.json` whose list
 * values stayed raw, and of one that was in fact a whole-file twin. Reads
 * the disk only for a derived file naming a directory.
 */
export function twinFormOf(path: string, value: string, match: { rule: string | null; extract?: string }): TwinForm {
  if (match.rule?.startsWith("derived:")) {
    const dir = directoryLineOf(value);
    if (dir !== null && isCanonicalDirectory(dir)) return { form: "own-text", shape: "directory-path", fields: 0 };
  }
  const x = extractSecretSpans(path, value, match.extract ? { extract: match.extract } : {});
  const form = twinDecision(x, byCatalogRule(match.rule));
  return { form, shape: x.shape, fields: form === "structured" ? x.spans.length : 0 };
}

/** The spans of an extraction, then the parts of those that merged others
 *  (`SecretSpan.parts`): every secret that gets a field row. A part's row
 *  is in no placeholder of the twin as such (its text is inside its span's
 *  placeholder), but its token masks a copy of it elsewhere in the file,
 *  and the value backstop holds its value (2026-10-10: a secret merged into
 *  a YAML flow item or an overlap union had no row of its own). A part has
 *  no `wire`, so its row is never bound to a registry. */
function spansAndParts(spans: readonly SecretSpan[]): SecretSpan[] {
  return [...spans, ...spans.flatMap((s) => s.parts ?? [])];
}

/** Mint (or reuse) the field symbols of a secret file and render its twin;
 *  null when the file has no known shape (whole-file twin). With
 *  `exhaustiveOk`, an exhaustive shape that found no secret value returns
 *  the file's own text as its twin, with no field. */
function mintFields(
  symbolMap: SymbolMap,
  baseSymbol: string,
  content: string,
  args: { path: string; sessionKey?: string },
  base: { confidentiality: ConfidentialityLevel; bindings?: string[] },
  dbPath?: string,
  extract?: string,
  exhaustiveOk = false,
  wireHosts = false,
): { shape: string; spans: SecretSpan[]; twin: string } | null {
  const x = extractSecretSpans(args.path, content, extract ? { extract } : {});
  const form = twinDecision(x, exhaustiveOk);
  if (form === "whole-file" || x.shape === null) return null;
  if (form === "own-text") return { shape: x.shape, spans: [], twin: content };
  const hash = getActiveFormat().extractHash(baseSymbol);
  if (hash === null) return null;
  const tokens = new Map<string, string>();
  const secrets = spansAndParts(x.spans);
  for (const span of secrets) {
    const key = {
      tool: REGISTRY_TOOL,
      field: span.key,
      value: span.value,
      origin: args.path,
      sessionKey: args.sessionKey,
      hash,
      confidentiality: base.confidentiality,
      // A credential in a comment (`SecretSpan.comment`, an old key no
      // program sends) is bound nowhere: the file's bindings are for the
      // values programs read. A label's `values:` entry naming it binds it
      // (the sync below, current-bindings.ts).
      bindings: span.comment ? undefined : wireHosts && span.wire ? withBinding(base.bindings, span.wire.host) : base.bindings,
      integrity: "trusted" as const,
    };
    const reused = findReusableSymbol(symbolMap, key);
    const name = reused ?? allocateSymbol(symbolMap, key, dbPath);
    if (wireHosts && span.wire && !span.comment) {
      // The grant is RECORDED (confidentiality.md §2.1, 2026-10-17), so the
      // bindings sync keeps exactly this host on this row whatever the label
      // binds, and never takes a host the label gave for one.
      recordWireGrant(symbolMap, name, span.wire.host, dbPath);
      // A row minted by an earlier launch (or an older arbiter) is reused by
      // value, whatever its bindings: give it its registry if it lacks it.
      const row = symbolMap.symbols.get(name)!;
      if (reused !== null && !(row.bindings ?? []).some((b) => b.toLowerCase() === span.wire!.host)) {
        row.bindings = withBinding(row.bindings ?? undefined, span.wire.host);
        persistSymbol(reused, row, dbPath);
        touchSymbolMap(symbolMap);
      }
    }
    tokens.set(span.key, name);
    // An ENCODED span's field stands for the decoded secret (what npm or pip
    // sends, §11.13.1). The file's own text of it (npm's base64 `_password`,
    // a percent-encoded URL password) is a credential too: it gets a row of
    // its own, unbound and in no twin, so the fingerprint scans still hold it.
    const text = content.slice(span.start, span.end);
    if (span.encoded && text !== span.value && !secrets.some((s) => s.key === `${span.key}.encoded`)) {
      const enc = {
        tool: REGISTRY_TOOL,
        field: `${span.key}.encoded`,
        value: text,
        origin: args.path,
        sessionKey: args.sessionKey,
        hash,
        confidentiality: base.confidentiality,
        bindings: base.bindings,
        integrity: "trusted" as const,
      };
      if (findReusableSymbol(symbolMap, enc) === null) allocateSymbol(symbolMap, enc, dbPath);
    }
  }
  const twin = renderStructuredTwin(content, x.spans, (s) => tokens.get(s.key)!);
  return { shape: x.shape, spans: x.spans, twin };
}

/** The files, relative to the launch HOME, whose wire-marked values are
 *  bound to their hosts (plan 10 §11.13.1): npm's user config and pip's two
 *  per-user config files; since 2026-10-21 (secret-discovery.md §2.10) the
 *  MCP configs of the editors and apps no supported agent reads in its own
 *  process (Cursor's, Claude Desktop's, Windsurf's, VS Code's user file),
 *  whose HTTP servers' Authorization credential goes to the host of the
 *  entry's own `url`. Each is twinned in every launch, so nothing in the
 *  agent's world writes the real file. NOT `~/.claude.json` or Codex's
 *  `config.toml`: the launch of their agent leaves them readable and
 *  writable to its world (its own state files), so a host a session wrote
 *  there would be granted to the next launch; nor a workspace `.mcp.json`,
 *  `.vscode/mcp.json` or `.cursor/mcp.json` (§11.6). Since 2026-10-22 the
 *  per-user configs of Gemini CLI, Zed and Continue too (no supported agent
 *  reads them); NOT OpenCode's or Goose's, which their agent's launch
 *  leaves writable to its world, as `.claude.json`. */
const HOME_WIRE_FILES: readonly string[] = [
  ".npmrc", ".config/pip/pip.conf", ".pip/pip.conf",
  ".cursor/mcp.json", ".config/Claude/claude_desktop_config.json", "Library/Application Support/Claude/claude_desktop_config.json",
  ".codeium/windsurf/mcp_config.json", ".config/Code/User/mcp.json", "Library/Application Support/Code/User/mcp.json",
  ".gemini/settings.json", ".config/zed/settings.json", ".continue/config.yaml", ".continue/config.json",
];

/** Is `path` one of the launch HOME's own wire files (`HOME_WIRE_FILES`:
 *  `~/.npmrc`, `~/.config/pip/pip.conf`, `~/.pip/pip.conf`, the editors'
 *  MCP configs)? A workspace copy, which the agent can write, never is.
 *  Without a home, no. */
export function isHomeWireFile(path: string, home: string | undefined): boolean {
  if (!home) return false;
  const p = resolve(path);
  return HOME_WIRE_FILES.some((rel) => p === resolve(join(home, rel)));
}

/** `bindings` with `host` added once (the file's own bindings first). */
function withBinding(bindings: string[] | undefined, host: string): string[] {
  const out = [...(bindings ?? [])];
  if (!out.some((b) => b.toLowerCase() === host)) out.push(host);
  return out;
}

/** Does a `NO_PROXY` list send requests for `host` (`name` or `name:port`)
 *  around the proxy? An entry matches the name exactly or as a domain suffix
 *  (`.corp` and `corp` both match `npm.corp`); `*` matches everything; ports
 *  are ignored. Pure. */
export function noProxyMatches(host: string, direct: readonly string[]): boolean {
  const name = host.toLowerCase().replace(/^\[|\]$/g, "").replace(/:\d+$/, "");
  for (const raw of direct) {
    const d = raw.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/:\d+$/, "").replace(/^\*?\./, "");
    if (d === "") continue;
    if (d === "*" || name === d || name.endsWith(`.${d}`)) return true;
  }
  return false;
}

/** Plan 10 §11.13.1: may npm be served this registered file's TWIN, the
 *  session proxy putting each token back at its registry? */
export interface WireServable {
  servable: boolean;
  /** Why (for the open decision's reason and the audit log). */
  why: string;
  /** The registries the file's tokens are bound to (servable only). */
  hosts: string[];
}

/** The wire twin's scheme rule for one symbol (plan 10 §11.13.1, 2026-10-03):
 *  `https` = put back only in an HTTPS request; `any` = its declared URL is
 *  `http://`, so plain HTTP too; null = not a wire credential (its bindings,
 *  if any, are a label's, which this rule does not touch). */
export type WireReleaseScheme = "https" | "any" | null;

/**
 * Which scheme a symbol's value may be put back over. Derived, never stored:
 *   - a FIELD row of a registered `.npmrc` / `pip.conf` (or `pip.ini`): the
 *     file's span of that field, re-extracted from the newest base row of its
 *     origin. A `wire` span answers by its `httpsOnly`; a span with no `wire`
 *     answers null; a field the current text no longer has (a row of older
 *     content, the unbound `.encoded` row) answers `https` (FAIL CLOSED: never
 *     plain HTTP for what may be a wire credential);
 *   - a pip index variable's row (`env:PIP_INDEX_URL`,
 *     `env:PIP_EXTRA_INDEX_URL`): `.password_http` (an `http://` index, the
 *     field says so since the row keeps no URL) answers `any`; any other field
 *     `https`;
 *   - a FIELD row of an agent's own key file a launch granted to a host
 *     (`grantScheme`, auth-grants.ts; agent-sign-in.md §3): `any` only for a
 *     plain-HTTP loopback grant at that destination, else `https`;
 *   - any other row: null.
 * Pure over the symbol table.
 */
export function wireReleaseScheme(
  symbolMap: SymbolMap,
  name: string,
  opts: {
    resolveLabel?: LabelLookup; cache?: Map<string, SecretSpan[] | null>;
    /** An auth grant's scheme for a field at the request's destination
     *  (auth-grants.ts `scheme`): consulted first, for registered file rows. */
    grantScheme?: (origin: string, field: string) => "https" | "any" | undefined;
  } = {},
): WireReleaseScheme {
  const row = symbolMap.symbols.get(name);
  if (!row || row.field === null || typeof row.origin !== "string") return null;
  // An auth grant (agent-sign-in.md §3): a key file's field, or an agent
  // key variable's row (§3.8, origin `env:NAME`).
  if ((row.tool === REGISTRY_TOOL || row.tool === ENV_TOOL) && opts.grantScheme) {
    const granted = opts.grantScheme(row.origin, row.field);
    if (granted !== undefined) return granted;
  }
  if (row.tool === ENV_TOOL) {
    if (!/^env:PIP_(EXTRA_)?INDEX_URL$/.test(row.origin)) return null;
    return row.field.endsWith(".password_http") ? "any" : "https";
  }
  if (row.tool !== REGISTRY_TOOL) return null;
  const shape = secretFileShape(row.origin);
  // An MCP config's HTTP server credential (secret-discovery.md §2.10) is
  // a wire credential too: its span says whether its URL is https.
  if (shape !== "npmrc" && shape !== "pip-conf" && mcpConfigKind(row.origin) === null) return null;
  // The field's OWN file version: the base row of that origin whose hash the
  // field symbol shares (a re-registered file's rows carry their own hash).
  const fmt = getActiveFormat();
  const hash = fmt.extractHash(name);
  if (hash === null) return "https";
  const cacheKey = `${row.origin}\u0000${hash}`;
  let spans = opts.cache?.get(cacheKey);
  if (spans === undefined) {
    let base: string | null = null;
    for (const [n, e] of symbolMap.symbols) {
      if (e.tool !== REGISTRY_TOOL || e.field !== null || e.origin !== row.origin) continue;
      if (fmt.extractHash(n) === hash) { base = e.value; break; }
    }
    const extract = pathConfidentiality(row.origin, undefined, opts.resolveLabel).extract;
    spans = base === null ? null : extractSecretSpans(row.origin, base, extract ? { extract } : {}).spans;
    opts.cache?.set(cacheKey, spans);
  }
  const span = spans?.find((s) => s.key === row.field);
  if (!span) return "https";
  if (!span.wire) return null;
  return span.wire.httpsOnly ? "https" : "any";
}

/**
 * Whether a registered `.npmrc` can be served to npm as its twin: every
 * secret value in it is one npm sends to the registry its own key names
 * (`span.wire`), and its field symbol is BOUND to that registry (which the
 * registration does for the launch HOME's file only, from the real file's
 * text); and nothing in the file sends npm around the session proxy
 * (`npmrcProxyBypassKeys`). Anything else (another file, an undecodable
 * `_password`, an unscoped token, an unbound field, a `cafile`) is not
 * servable, and npm keeps today's raw read. Pure over the symbol table.
 */
export function wireServableTwin(symbolMap: SymbolMap, path: string, opts: { direct?: readonly string[] } = {}): WireServable {
  const no = (why: string): WireServable => ({ servable: false, why, hosts: [] });
  if (basename(path) !== ".npmrc") return no("not an .npmrc");
  let base: { name: string; value: string; created: number } | null = null;
  for (const [name, e] of symbolMap.symbols) {
    if (e.obsoleted_at !== null || e.tool !== REGISTRY_TOOL || e.field !== null) continue;
    if (e.origin !== path || !isSecret(e.confidentiality) || e.integrity !== "trusted") continue;
    if (base === null || e.created_at > base.created) base = { name, value: e.value, created: e.created_at };
  }
  if (base === null) return no("not registered");
  const x = extractSecretSpans(path, base.value);
  if (x.shape !== "npmrc" || x.spans.length === 0) return no("no token in the file");
  const bypass = npmrcProxyBypassKeys(base.value);
  if (bypass.length > 0) return no(`its ${bypass.join(", ")} would send npm around the session proxy`);
  const fmt = getActiveFormat();
  const hash = fmt.extractHash(base.name);
  if (hash === null) return no("no field symbols");
  const level = symbolMap.symbols.get(base.name)!.confidentiality;
  const hosts: string[] = [];
  for (const span of x.spans) {
    // A credential in a comment line (the twin's credential belt): npm never
    // reads it, so nothing needs it put back.
    if (span.comment) continue;
    if (!span.wire) return no(`${span.key} is not a value npm sends as written to a named registry`);
    const row = symbolMap.symbols.get(fmt.generate({ tool: REGISTRY_TOOL, hash, field: span.key, level }));
    if (!row || row.obsoleted_at !== null || row.value !== span.value) return no(`${span.key} has no field symbol`);
    if (!(row.bindings ?? []).some((b) => b.toLowerCase() === span.wire!.host)) return no(`${span.key} is not bound to ${span.wire.host}`);
    if (noProxyMatches(span.wire.host, opts.direct ?? [])) return no(`npm reaches ${span.wire.host} directly (NO_PROXY), where nothing puts the token back`);
    if (!hosts.includes(span.wire.host)) hosts.push(span.wire.host);
  }
  if (hosts.length === 0) return no("no token in the file");
  return { servable: true, why: `the session proxy puts every token back at its own registry (${hosts.join(", ")})`, hosts };
}

/**
 * The structured twin text of a registered path, re-rendered from the symbol
 * table (the base row's bytes + the field rows' names), or null when the path
 * is not registered or has no field rows. The read-twin rule compares a Read
 * result against this: text that is a substring of it carries no secret byte.
 */
export function structuredTwinFor(
  symbolMap: SymbolMap,
  path: string,
  opts: { home?: string; resolveLabel?: LabelLookup } = {},
): string | null {
  return structuredTwinWithSecretsFor(symbolMap, path, opts)?.text ?? null;
}

/**
 * `structuredTwinFor` with the file's secret texts (each value, and the
 * file's own spelling of it): the same base row, the same rendering. The
 * key listing test (plan 10 §11.8) refuses a twin line holding one
 * (a short value the generator left glued inside a longer word).
 */
export function structuredTwinWithSecretsFor(
  symbolMap: SymbolMap,
  path: string,
  opts: { home?: string; resolveLabel?: LabelLookup; pieces?: boolean } = {},
): RegisteredTwin | null {
  // The base is the REGISTRY's own row (review of !1604, 2026-10-17): a
  // proxy's `Read` row on the same path (a Read the proxy masked whole; it
  // carries the call id) is newer than the registration, and as the base it
  // rendered no twin (no field rows under its hash). Every later Read of the
  // twin was then masked whole, minting another such row: a Read that never
  // recovered, and the key listing and `cat .env` stopped answering.
  let base: { name: string; value: string; created: number } | null = null;
  for (const [name, e] of symbolMap.symbols) {
    if (e.obsoleted_at !== null || e.field !== null || !isRegisteredFileRow(e)) continue;
    if (e.origin !== path || !isSecret(e.confidentiality)) continue;
    if (base === null || e.created_at > base.created) base = { name, value: e.value, created: e.created_at };
  }
  if (base === null) return null;
  const twin = renderRegisteredTwin(symbolMap, path, base.name, base.value, opts);
  // `pieces` (the key listing test, plan 10 §11.8): the value backstop's
  // pieces of that base row, as the value index holds them.
  if (twin === null || opts.pieces !== true) return twin;
  return { ...twin, pieces: valueFingerprints(base.value, 0, { bareTokens: true, twin }) };
}

/**
 * The paths of every registered file (plan 10 §11.8, "A key listing"):
 * the origins of the active base rows the registry minted from a labelled
 * file (`isRegisteredFileRow`, no field, a secret level). Sorted. No twin is
 * rendered: the key listing test renders only the files a command
 * names (`structuredTwinWithSecretsFor`). One pass over the symbol table;
 * the caller caches it.
 */
export function registeredFilePaths(symbolMap: SymbolMap): string[] {
  const paths = new Set<string>();
  for (const e of symbolMap.symbols.values()) {
    if (e.obsoleted_at !== null || e.field !== null || !isRegisteredFileRow(e) || !isSecret(e.confidentiality)) continue;
    paths.add(e.origin as string);
  }
  return [...paths].sort();
}

/** A registered file's structured twin as one base row renders it, with the
 *  file's secret texts (each span's value, and the file's own text of it
 *  when that differs: an encoded or quoted value). */
export interface RegisteredTwin {
  text: string;
  secrets: string[];
  /** With `pieces` asked (`structuredTwinWithSecretsFor`): the value
   *  backstop's pieces of the base row (egress-fingerprint.ts
   *  `valueFingerprints`, its file row's bare tokens included). */
  pieces?: string[];
  /** A personal document's twin (2026-10-19, secret-discovery.md §2.7, "A
   *  person's name"): the field rows that hold a person's name
   *  (`SecretSpan.name`), which the value index leaves out
   *  (`documentNameRows`); their texts that no other field of the file
   *  holds (`names`); and the file's lines (trimmed) whose every secret is
   *  such a name (`nameLines`: `Holder: Alex Demo`), no piece of the base
   *  row (egress-fingerprint.ts `ValueTwin`). Absent when none. */
  nameRows?: string[];
  names?: string[];
  nameLines?: string[];
}

/** Render the structured twin of base row `baseName` (value `value`, path
 *  `path`): null when the file has no shape, no secret value, or any field
 *  row (a part's too, `spansAndParts`) is missing, obsolete or holds
 *  another value (not this file's rows). */
function renderRegisteredTwin(
  symbolMap: SymbolMap,
  path: string,
  baseName: string,
  value: string,
  opts: { home?: string; resolveLabel?: LabelLookup },
): RegisteredTwin | null {
  const extract = pathConfidentiality(path, opts.home, opts.resolveLabel).extract;
  const x = extractSecretSpans(path, value, extract ? { extract } : {});
  if (x.shape === null || x.spans.length === 0) return null;
  const fmt = getActiveFormat();
  const hash = fmt.extractHash(baseName);
  if (hash === null) return null;
  const level = symbolMap.symbols.get(baseName)!.confidentiality;
  const tokens = new Map<string, string>();
  const secrets = new Set<string>();
  const nameRows: string[] = [];
  const nameTexts = new Set<string>();
  const otherTexts = new Set<string>();
  for (const span of spansAndParts(x.spans)) {
    const name = fmt.generate({ tool: REGISTRY_TOOL, hash, field: span.key, level });
    const row = symbolMap.symbols.get(name);
    if (!row || row.obsoleted_at !== null || row.value !== span.value) return null; // not this file's rows
    tokens.set(span.key, name);
    secrets.add(span.value);
    secrets.add(value.slice(span.start, span.end));
    if (span.name) { nameRows.push(name); nameTexts.add(span.value); } else { otherTexts.add(span.value); otherTexts.add(value.slice(span.start, span.end)); }
  }
  secrets.delete("");
  const twin: RegisteredTwin = { text: renderStructuredTwin(value, x.spans, (s) => tokens.get(s.key)!), secrets: [...secrets] };
  // A name that is also another field's text is that field's: still a fingerprint.
  const names = [...nameTexts].filter((t) => t !== "" && !otherTexts.has(t));
  if (names.length === 0) return twin;
  return { ...twin, nameRows: nameRows.filter((n) => names.includes(symbolMap.symbols.get(n)!.value)), names, nameLines: documentNameLines(value, x.spans, new Set(names)) };
}

/** The lines of `value` (trimmed) on which every secret span is a name of
 *  `names` (`SecretSpan.name`) and at least one is: the twin keeps their
 *  label and Markdown markers, so the name is the line's only secret. Pure. */
function documentNameLines(value: string, spans: readonly SecretSpan[], names: ReadonlySet<string>): string[] {
  const out = new Set<string>();
  const verdict = new Map<number, boolean>(); // line start -> every span a name
  for (const s of spans) {
    const lineStart = value.lastIndexOf("\n", s.start - 1) + 1;
    const lineEnd = value.indexOf("\n", s.start);
    const crosses = lineEnd !== -1 && s.end > lineEnd;
    const ok = s.name === true && names.has(s.value) && !crosses;
    verdict.set(lineStart, (verdict.get(lineStart) ?? true) && ok);
  }
  for (const [start, ok] of verdict) {
    if (!ok) continue;
    const end = value.indexOf("\n", start);
    out.add(value.slice(start, end === -1 ? value.length : end).trim());
  }
  return [...out];
}

/**
 * The field rows of the registered files that hold a person's name in a
 * personal document's twin (2026-10-19, secret-discovery.md §2.7, "A
 * person's name"): each is a placeholder in its file's twin, but no
 * fingerprint of the value backstop or the egress tripwire, so another
 * output that merely mentions the name (a mail quoting the user) reaches
 * the model as it is. Only the base rows whose path's twin is the
 * document twin (`DOCUMENT_TWIN_EXTRACT`) are rendered
 * (`registeredFileTwin`). Pure over the symbol table and the label lookup.
 */
export function documentNameRows(
  symbolMap: SymbolMap,
  opts: { resolveLabel?: LabelLookup } = {},
): Set<string> {
  const out = new Set<string>();
  for (const [name, e] of symbolMap.symbols) {
    if (e.obsoleted_at !== null || e.field !== null || !isRegisteredFileRow(e) || !isSecret(e.confidentiality)) continue;
    if (pathConfidentiality(e.origin as string, undefined, opts.resolveLabel).extract !== DOCUMENT_TWIN_EXTRACT) continue;
    const twin = registeredFileTwin(symbolMap, name, { resolveLabel: opts.resolveLabel });
    for (const r of twin?.nameRows ?? []) out.add(r);
  }
  return out;
}

/**
 * The structured twin of the registered file whose BASE row is `name` (plan
 * 10 §11.8, a twin line is no fingerprint): the twin as that row's own value
 * renders it, and the file's secret texts. Null unless `name` is an active
 * base row registered from a labelled file (`isRegisteredFileRow`, no field,
 * a secret level) whose file has a structured twin. The value backstop drops
 * from that row's line fingerprints each line this twin carries verbatim and
 * that holds no secret text (egress-fingerprint.ts `valueFingerprints`).
 */
export function registeredFileTwin(
  symbolMap: SymbolMap,
  name: string,
  opts: { home?: string; resolveLabel?: LabelLookup } = {},
): RegisteredTwin | null {
  const e = symbolMap.symbols.get(name);
  if (!e || e.obsoleted_at !== null || e.field !== null || !isRegisteredFileRow(e) || !isSecret(e.confidentiality)) return null;
  return renderRegisteredTwin(symbolMap, e.origin as string, name, e.value, opts);
}

/**
 * The registered file a FIELD symbol belongs to, with that file's structured
 * twin text and secret texts (plan 10 §11.8, the exec-output twin rule): null unless `token`
 * is an active field row of a registered secret file (tool Read, a field, a
 * secret level, trusted) and the file still has a twin. `cache` is keyed by
 * path, so one output's tokens re-render each file once.
 */
export function structuredTwinOfField(
  symbolMap: SymbolMap,
  token: string,
  opts: { home?: string; resolveLabel?: LabelLookup; cache?: Map<string, RegisteredTwin | null> } = {},
): { path: string; text: string; secrets: string[] } | null {
  const row = symbolMap.symbols.get(token);
  if (!row || row.obsoleted_at !== null || row.tool !== REGISTRY_TOOL || row.field === null) return null;
  if (!isSecret(row.confidentiality) || row.integrity !== "trusted" || typeof row.origin !== "string") return null;
  const path = row.origin;
  let twin = opts.cache?.get(path);
  if (twin === undefined) {
    twin = structuredTwinWithSecretsFor(symbolMap, path, { ...(opts.home ? { home: opts.home } : {}), ...(opts.resolveLabel ? { resolveLabel: opts.resolveLabel } : {}) });
    opts.cache?.set(path, twin);
  }
  // The file's secret texts ride along: the exec-output rule refuses an
  // output holding one (a glued short value, 2026-10-17).
  return twin === null ? null : { path, text: twin.text, secrets: twin.secrets };
}

/**
 * The registered file a BASE symbol stands for when that file's twin is the
 * WHOLE-FILE twin (plan 10 §11.8, "A document's own twin"): the symbol alone,
 * then the file's own final line terminator (`registerSecret`'s `terminator`,
 * confidentiality.md §7.2). Null unless `token` is an active base row the
 * registry minted from a labelled file (`isRegisteredFileRow`: tool Read, no
 * call id, trusted, an origin path; no field; a secret level) AND that row's
 * own value makes the whole-file twin under the label in force
 * (`twinFormOf`: no shape, or a shape that found no secret value and is not
 * an exhaustive one on the catalog's word). The catalog's word is read under
 * the arbiter's HOME and every HOME in `homes` (`twinMatchOf`, the HOMEs
 * `isOwnTextTwin` takes: the live launches', the human-plane
 * registrations'), so a config under a launch HOME the arbiter does not
 * share is the own-text twin the guard serves, not a whole-file one
 * (2026-10-17). A file whose twin is structured or its own text answers
 * null: the guard never serves its token alone. Pure over the symbol table
 * (and the label lookup).
 */
export function wholeFileTwinOfBase(
  symbolMap: SymbolMap,
  token: string,
  opts: { homes?: readonly string[]; resolveLabel?: LabelLookup } = {},
): { path: string; terminator: "" | "\n" | "\r\n" } | null {
  const row = symbolMap.symbols.get(token);
  if (!row || row.obsoleted_at !== null || row.field !== null || !isRegisteredFileRow(row) || !isSecret(row.confidentiality)) return null;
  const path = row.origin as string;
  const form = twinFormOf(path, row.value, twinMatchOf(path, opts));
  if (form.form !== "whole-file") return null;
  return { path, terminator: finalTerminator(row.value) };
}

/**
 * The whole-file twin the guard serves for `path` NOW (plan 10 §11.8, "A
 * document's own twin", the read leg): the NEWEST active base row the
 * registry minted for that path (`isRegisteredFileRow`, no field, a secret
 * level; the latest registration is the twin on disk), when that row makes
 * the whole-file twin (`wholeFileTwinOfBase`). Null for a path with no such
 * row, a structured or own-text twin, or a newest row that is not one. A
 * proxy's own Read row (it has a call id) is never a candidate.
 */
export function wholeFileTwinFor(
  symbolMap: SymbolMap,
  path: string,
  opts: { homes?: readonly string[]; resolveLabel?: LabelLookup } = {},
): { token: string; terminator: "" | "\n" | "\r\n" } | null {
  let base: { name: string; created: number } | null = null;
  for (const [name, e] of symbolMap.symbols) {
    if (e.obsoleted_at !== null || e.field !== null || e.origin !== path || !isRegisteredFileRow(e) || !isSecret(e.confidentiality)) continue;
    // `>=`: of two rows minted in the same millisecond, the later one (the
    // table keeps insertion order, and loads in it).
    if (base === null || e.created_at >= base.created) base = { name, created: e.created_at };
  }
  if (base === null) return null;
  const twin = wholeFileTwinOfBase(symbolMap, base.name, opts);
  return twin === null ? null : { token: base.name, terminator: twin.terminator };
}

/**
 * Is `value`, the text of the registered file at `path`, that file's
 * OWN-TEXT twin under the law in force (plan 10 §11.13, "A config with no
 * secret reaches the model as its text", 2026-10-17)? Exactly when:
 *   - the shape is EXHAUSTIVE (`shapeIsExhaustive`: `~/.ssh/config`,
 *     `pip.conf`, git's credential store) and its extraction, the credential
 *     belt of !1621 included, finds no secret value (`twinFormOf` answers
 *     `own-text`): every place the format can hold a secret was read and
 *     found public, and an unknown construct is masked (a field), so a file
 *     holding one is a structured twin, not this;
 *   - the CATALOG labels the path under one of `homes` (the arbiter's own
 *     HOME always, and the HOMEs the human plane named: a launch's, a
 *     registration's), and no human or derived label covers it under any of
 *     them (such a label says the file itself is the secret).
 * Anything else (no shape, a span, a label, a path no attested HOME's
 * catalog names) is false: fail closed, the file stays one handle. Pure over
 * the label lookup.
 */
export function isOwnTextTwin(
  path: string,
  value: string,
  opts: { homes?: readonly string[]; resolveLabel?: LabelLookup } = {},
): boolean {
  if (typeof value !== "string" || value === "") return false;
  const match = twinMatchOf(path, opts);
  if (!byCatalogRule(match.rule)) return false;
  const form = twinFormOf(path, value, match);
  return form.form === "own-text" && shapeIsExhaustive(form.shape);
}

/**
 * The match the twin of the registered file at `path` is decided by
 * (`twinFormOf`'s `match`), read under the arbiter's own HOME and each HOME
 * of `homes` (the HOMEs the human plane named: the live launches', the
 * launcher's registrations'), as the guard reads it (plan 10 §11.13,
 * 2026-10-17): a human or derived label under any of them (it says the file
 * itself is the secret, so no exhaustive shape twins as its own text), else
 * the first CATALOG match at a secret level, else the arbiter's own HOME's
 * match. `isOwnTextTwin`, `wholeFileTwinOfBase` and `whyPath`'s `twin` all
 * decide by it, so `mandu why` and the exec-output and read legs give the
 * twin the guard serves under a launch HOME the arbiter does not share.
 * With no `homes`, exactly the arbiter's HOME's match. Pure over the label
 * lookup.
 */
export function twinMatchOf(
  path: string,
  opts: { homes?: readonly string[]; resolveLabel?: LabelLookup } = {},
): { rule: string | null; extract?: string } {
  const own = pathConfidentiality(path, undefined, opts.resolveLabel);
  let catalog: SecretCatalogMatch | null = null;
  for (const m of [own, ...(opts.homes ?? []).map((home) => pathConfidentiality(path, home, opts.resolveLabel))]) {
    if (m.rule === null) continue;
    if (!byCatalogRule(m.rule)) return ruleOf(m);
    if (isSecret(m.level)) catalog ??= m;
  }
  return ruleOf(catalog ?? own);
}

function ruleOf(m: SecretCatalogMatch): { rule: string | null; extract?: string } {
  return { rule: m.rule, ...(m.extract ? { extract: m.extract } : {}) };
}

/**
 * The OWN-TEXT twin the guard serves for `path` now (plan 10 §11.13,
 * 2026-10-17): the NEWEST active base row the registry minted for that path
 * (`isRegisteredFileRow`, no field, a secret level; the latest registration
 * is the twin on disk), when its own value is the file's own-text twin
 * (`isOwnTextTwin`): its symbol and that text. Null otherwise: no such row,
 * or a newest row whose twin is structured or whole-file. A proxy's own Read
 * row (it has a call id) is never a candidate.
 */
export function ownTextTwinFor(
  symbolMap: SymbolMap,
  path: string,
  opts: { homes?: readonly string[]; resolveLabel?: LabelLookup } = {},
): { token: string; text: string } | null {
  let base: { name: string; value: string; created: number } | null = null;
  for (const [name, e] of symbolMap.symbols) {
    if (e.obsoleted_at !== null || e.field !== null || e.origin !== path || !isRegisteredFileRow(e) || !isSecret(e.confidentiality)) continue;
    if (base === null || e.created_at >= base.created) base = { name, value: e.value, created: e.created_at };
  }
  if (base === null || !isOwnTextTwin(path, base.value, opts)) return null;
  return { token: base.name, text: base.value };
}

/**
 * Does row `name` hold nothing but (a piece of) an own-text twin (plan 10
 * §11.13, 2026-10-17), so the value backstop must not count it? Two kinds,
 * both WHOLE-text rows (no field: a field row is a secret value, and an old
 * registration's field stays a fingerprint even when the value now sits in
 * a public place of the file):
 *   - a registered file's base row whose own value is its own-text twin
 *     (`isOwnTextTwin`): its text is what the model is shown;
 *   - any other row on that file's path (a proxy's Read it masked whole
 *     before) whose value is one contiguous piece of the file's own-text twin
 *     now (`ownTextTwinFor`).
 * Pure over the symbol table and the label lookup.
 */
export function isOwnTextRow(
  symbolMap: SymbolMap,
  name: string,
  opts: { homes?: readonly string[]; resolveLabel?: LabelLookup } = {},
): boolean {
  const e = symbolMap.symbols.get(name);
  if (!e || e.obsoleted_at !== null || e.field !== null || typeof e.origin !== "string" || !e.origin.startsWith("/") || e.value === "") return false;
  if (isRegisteredFileRow(e)) return isOwnTextTwin(e.origin, e.value, opts);
  const twin = ownTextTwinFor(symbolMap, e.origin, opts);
  return twin !== null && twin.text.includes(e.value);
}

/**
 * Register ONE environment variable's secret (plan 10 §11.4). The launcher
 * holds the value already (it is the launcher's own environment), so the
 * value crosses the owner-only socket once; the agent's environment then
 * carries the symbol. Not a secret ⇒ `{symbol: null}`; never throws.
 */
export function registerEnvSecret(
  symbolMap: SymbolMap,
  args: { name: string; value: string; sessionKey?: string; rules?: EnvSecretRules; bindings?: readonly string[] },
  dbPath?: string,
): RegisterEnvSecretResult {
  const span = envSecretSpan(args.name, args.value, args.rules ?? {});
  if (span === null) return { symbol: null, reason: `not a secret variable: ${args.name}` };
  // A sourced variable's bound hosts (policy.yaml env.sources[].bindings):
  // the egress gate releases its value there without an ask. Plan 10
  // §11.13.1: pip's index variable's password is bound to its index host,
  // derived from the value itself (the launcher's environment, the human's).
  const bindings = span.wire ? withBinding(args.bindings ? [...args.bindings] : undefined, span.wire.host) : args.bindings ? [...args.bindings] : [];
  const key = {
    tool: ENV_TOOL,
    field: span.key,
    value: span.value,
    origin: `env:${args.name}`,
    sessionKey: args.sessionKey,
    confidentiality: "no-model" as const,
    integrity: "trusted" as const,
    ...(bindings.length ? { bindings } : {}),
  };
  const reused = findReusableSymbol(symbolMap, key);
  const symbol = reused ?? allocateSymbol(symbolMap, key, dbPath);
  // A row an earlier launch minted is reused by value: it takes this
  // launch's bindings (the law's env.sources / models[].token_env in force,
  // and the wire host), so a binding added or removed since applies.
  if (reused !== null) {
    const row = symbolMap.symbols.get(reused)!;
    const stored = row.bindings ?? [];
    if (stored.length !== bindings.length || !bindings.every((b) => stored.includes(b))) {
      row.bindings = bindings.length > 0 ? [...bindings] : null;
      persistSymbol(reused, row, dbPath);
      touchSymbolMap(symbolMap);
    }
  }
  const twin = renderStructuredTwin(args.value, [span], () => symbol);
  return {
    symbol,
    twin,
    ...(span.wire ? { wireHost: span.wire.host } : {}),
    reason: `${reused !== null ? "already registered" : "registered"} (env:${span.key === args.name ? "value" : "url-password"})`,
  };
}

/**
 * Every registered secret: an active, secret-labeled symbol whose origin is a
 * filesystem path. Derived from the symbol table (no second store to keep in
 * sync). Sorted by path so callers/tests see a stable order.
 */
export function listSecretRegistry(symbolMap: SymbolMap): SecretRegistryEntry[] {
  const out: SecretRegistryEntry[] = [];
  const fieldCount = new Map<string, number>(); // base name → field rows
  // A field's own bindings (plan 10 §11.13.1: an `.npmrc` token bound to its
  // registry) are standing releases of the file too: §6 wants them visible.
  const fieldBindings = new Map<string, string[]>();
  for (const [name, e] of symbolMap.symbols) {
    if (e.obsoleted_at !== null || e.tool !== REGISTRY_TOOL || e.field === null) continue;
    const dot = name.indexOf(".");
    if (dot < 0) continue;
    const base = name.slice(0, dot);
    fieldCount.set(base, (fieldCount.get(base) ?? 0) + 1);
    if (e.bindings && e.bindings.length) fieldBindings.set(base, [...(fieldBindings.get(base) ?? []), ...e.bindings]);
  }
  for (const [name, e] of symbolMap.symbols) {
    if (e.obsoleted_at !== null) continue;
    if (e.tool !== REGISTRY_TOOL) continue;
    // A structured twin's FIELD row (`<base>.KEY`, same origin as its base)
    // belongs to its base entry. Other field-ful Read rows (the proxy's
    // `content` symbols of a labeled file) are entries of their own, as before.
    if (e.field !== null) {
      const dot = name.indexOf(".");
      const base = dot > 0 ? symbolMap.symbols.get(name.slice(0, dot)) : undefined;
      if (base && base.field === null && base.origin === e.origin) continue;
    }
    if (!isSecret(e.confidentiality)) continue;
    if (e.integrity !== "trusted") continue; // registry entries only
    if (!e.origin || !e.origin.startsWith("/")) continue;
    out.push({
      path: e.origin,
      symbol: name,
      fields: fieldCount.get(name) ?? 0,
      bindings: [...new Set([...(e.bindings ?? []), ...(fieldBindings.get(name) ?? [])])],
      level: e.confidentiality,
    });
  }
  return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/**
 * The placeholders a real send of registered file `path` carries (tour 1,
 * 2026-10-05; policy-surface.md §4 "Test a flow"): for every ACTIVE
 * registration of the file (a base row of {@link isRegisteredFileRow}, no
 * field, a secret level, origin exactly `path`), its active field rows (the
 * structured twin's `<base>.KEY` symbols), or the base row itself when it has
 * none (the whole-file twin). Every registration counts, not just the newest:
 * a changed file keeps its older rows active, and which one a session's twin
 * carries depends on when it was launched, so a tester that credits a human
 * answer must find it on all of them (fail-closed: an answer covering only
 * some never reads as a release). Each name with its level. Empty when the
 * file was never registered. Pure over the symbol table.
 */
export function registeredFileSymbols(symbolMap: SymbolMap, path: string): Array<{ symbol: string; level: ConfidentialityLevel }> {
  const bases: string[] = [];
  for (const [name, e] of symbolMap.symbols) {
    if (e.obsoleted_at !== null || e.field !== null || !isRegisteredFileRow(e)) continue;
    if (e.origin !== path || !isSecret(e.confidentiality)) continue;
    bases.push(name);
  }
  const out: Array<{ symbol: string; level: ConfidentialityLevel }> = [];
  for (const base of bases) {
    const fields: Array<{ symbol: string; level: ConfidentialityLevel }> = [];
    for (const [name, e] of symbolMap.symbols) {
      if (!name.startsWith(base + ".") || e.obsoleted_at !== null || e.field === null) continue;
      if (!isRegisteredFileRow(e) || e.origin !== path) continue;
      fields.push({ symbol: name, level: e.confidentiality });
    }
    if (fields.length > 0) out.push(...fields);
    else out.push({ symbol: base, level: symbolMap.symbols.get(base)!.confidentiality });
  }
  return out;
}

/** Test/debug helper: has this exact content already been symbolized? */
export function symbolsForValue(symbolMap: SymbolMap, value: string): string[] {
  return findSymbolsByValue(symbolMap, value);
}
