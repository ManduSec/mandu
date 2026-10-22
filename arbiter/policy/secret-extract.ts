/**
 * secret-extract — which SPANS of a secret file are the secret
 * (docs/design/confidentiality/confidentiality-plan-10-flow-taint.md §2.4, the structured twin).
 *
 * Plan 4′'s twin replaced the WHOLE file with one symbol, so every program that
 * parses the file (a shell sourcing a dotenv, psql reading ~/.pgpass, the aws
 * CLI) got a token where it expected structure. This module finds the secret
 * VALUES inside a file of a known shape so the twin can keep the keys raw and
 * replace each value with its own field symbol
 * (`STRIPE_KEY=$MDU:nomodel_Read[9bbd].STRIPE_KEY`). A file of no known shape, a
 * binary file, or one above the size floor extracts NOTHING and stays a
 * whole-file twin: the fail-safe direction is "mask more", never "expose".
 *
 * Pure: a function of (path, content, options). The arbiter calls it from
 * `registerSecret`; nothing here touches the disk or the symbol table.
 *
 * Shapes (the catalog's basename shapes plus the consumer files a developer
 * actually has): dotenv, INI (`~/.aws/credentials`, `.pypirc`), `.pgpass`,
 * `.netrc`, `.npmrc`, YAML by key name (`gh/hosts.yml`), JSON by key name
 * (`secrets*.json`), and three configuration files that hold a secret only in
 * known places (`ssh-config`, `pip-conf`, `git-credentials`, 2026-10-02). A
 * `paths[].extract` regex (one capturing group) overrides the shape, the same
 * contract as Claude Code's `credentials.files.extract`.
 *
 * EXHAUSTIVE shapes (`shapeIsExhaustive`): for those three the extractor reads
 * every place the format can hold a secret and masks any line it cannot read,
 * so finding NO secret span means the file holds none, and the twin is the
 * file's own text. Every other shape keeps the fail-safe: no span, whole-file
 * twin (a `secrets.json` whose keys do not look secret is still a secret). A
 * whole-file twin of `~/.ssh/config` or of a `pip.conf` with no credential
 * broke the program that parses it (plan 10 §11.13).
 *
 * Values that are URLs with a password (`postgres://u:pw@host/db`) mask ONLY
 * the password component, in every shape: the host, database and user stay
 * usable and the password is the symbol.
 *
 * LIST ITEMS (2026-10-09). A list holds no key, so the key-name rule never
 * saw its values: in a labelled `.mcp.json` whose `env` block had one
 * secret-looking key, every `args` value stayed raw in the twin
 * (`"--api-key", "…"`, `"--token=…"`, a database URL's password). Now a
 * string item of a JSON array, a YAML sequence or a TOML array is masked
 * when Mandu recognizes a secret in it (`listItemSpans`): a URL's password,
 * a credential format the content detector knows, the item after a
 * secret-named flag (`--api-key X`), the value of a secret-named
 * `--flag=X`, `NAME=X` or `Header: X` (also among the words of an item
 * that is a command line, `sh -c "…"`), and every item of a list under a
 * secret-looking key. Field names are `<list>.<index>` (`args.3`). They
 * only add to a file whose keys gave a secret span: one with none stays a
 * whole-file twin. What stays raw: a value under a key that does not look
 * secret, and a list item none of those rules recognizes (a short
 * word-like password on its own); the user's way out is `extract:` or
 * `readers:` (guarantees.md §3). 2026-10-10: `--auth`, `--pat` and the
 * password of `-u user:password`; a placeholder in a plain YAML flow item
 * is single-quoted so the twin still parses; a block scalar's text is no
 * YAML; a list that never closes or nests past `MAX_LIST_DEPTH` hides the
 * file whole; and every walk is linear in the file (a list item, a YAML
 * line or a JSON string of an agent-written file could make one take
 * hours, and `mandu why` runs it on demand from the data socket).
 *
 * Mandu-new (no reference origin).
 */
import { githubTokenChecksumOk, isStandIn, locateSecretShapes, looksLikeSecretValue, type SecretShape, type ShapeSpan } from "./secret-detectors.js";
import { locateBareSecretTokens } from "./egress-fingerprint.js";
import { passwordKind } from "./credential-names.js";
import { DOCUMENT_TWIN_EXTRACT, documentLineLabel, documentNameField } from "./personal-documents.js";
import { isIP } from "node:net";
import { codexTomlReading, mcpConfigKindOf, mcpReference, mcpServerEntries, mcpUrlHost, mcpWholeReference, type McpServerEntry } from "./mcp-config.js";

export interface SecretSpan {
  /** Field name for the symbol (`KEY`, `default.aws_secret_access_key`,
   *  `DATABASE_URL.password`). Unique within one extraction. */
  key: string;
  /** Byte offsets into `content`, end-exclusive. Spans never overlap and are
   *  returned in ascending order. */
  start: number;
  end: number;
  /** The secret bytes themselves (`content.slice(start, end)`). */
  value: string;
  /** Dotenv only: the twin must SINGLE-QUOTE the masked value, or a shell
   *  that sources the file expands `$MDU` as a variable and the token comes
   *  out as `:nomodel_Read[…]` (seen live, 2026-09-24). When set, `[start, end)`
   *  is the WHOLE value region (existing quotes included) and the twin
   *  writes `'${prefix}${token}${suffix}'` in its place, `prefix`/`suffix`
   *  being the unquoted text around the secret inside the value. A value the
   *  file single-quotes keeps its own form; an unquoted or double-quoted one
   *  gains the quotes (plan 10 §2.4.1: no other form is literal to every
   *  loader). `prefix`/`suffix` never hold a quote, a backslash or a line
   *  break. */
  wrap?: { prefix: string; suffix: string };
  /** Plan 10 §11.13.1 (`.npmrc`, `pip.conf`): the program sends this value
   *  to `host`, the registry or index its own key or URL names, in one
   *  header: `bearer` (`Authorization: Bearer <value>`) or `basic` (HTTP
   *  Basic: verbatim as npm's `_auth`, or as the user or password inside the
   *  `user:password` pair, which the session proxy decodes). The proxy can
   *  then put it back in place of its symbol there. The registration binds
   *  the field symbol to `host` for the launch HOME's own file only.
   *  `httpsOnly` (2026-10-03, maintainer decision): the credential's own
   *  declared URL is not `http://`, so it is put back only in an HTTPS
   *  request; plain HTTP to the same host gets nothing (registry.ts
   *  `wireReleaseScheme`, the arbiter's egress gate). */
  wire?: { host: string; scheme: "bearer" | "basic"; httpsOnly: boolean };
  /** The file holds an ENCODING of `value` (plan 10 §11.13.1, 2026-10-03):
   *  `base64` (npm's `_password`, which npm base64-decodes before use) or
   *  `percent` (a URL's user or password in `pip.conf`, which pip
   *  percent-decodes). `value` is then the DECODED secret, the form the
   *  program sends, and `[start, end)` the encoded text in the file. The
   *  twin writes the same encoding of the token, so the program decodes it
   *  back into the token, and a URL keeps parsing (a raw token's `[`, `]`
   *  and `:` break Python's URL parser in the user-information part). */
  encoded?: "base64" | "percent";
  /** `ssh-config` only (plan 10 §11.13.3): a command ssh would run that the
   *  twin withholds. The twin writes, in place of the whole command, a
   *  command of Mandu's own that prints `withheldCommandMessage` (which
   *  file, which line, which keyword, why, the way out; never the command
   *  text) and fails; the field symbol rides along as an unused argument. */
  withheld?: WithheldCommand;
  /** The secrets of a span that MERGED several rules' spans (2026-10-10):
   *  `finishMerged`'s union of overlapping spans (`--api-key key=https://u:PW@h`)
   *  and `quotedPlainFlowItems`' one placeholder over a YAML flow item. The
   *  span's own `value` is then the covered text, which is no secret any
   *  program reads as one, so each covered secret is kept here with its own
   *  field name (unique among every span's and part's) and `value` (and
   *  `encoded`, with its own `[start, end)` inside the span). The twin
   *  writes a copy of a part's secret elsewhere in the file as the part's
   *  own token (`twinNeedles`), and the registry mints each part a field
   *  row of its own, in no placeholder of the twin but held by the value
   *  backstop (registry.ts `mintFields`). Before this, a copy of a merged
   *  secret under another key stayed raw in the twin the model reads. A
   *  part has no parts, `wire`, `wrap` or `withheld`; a part that is the
   *  span's own secret is left out (`withSettledParts`). */
  parts?: SecretSpan[];
  /** The credential belt found this span in a COMMENT line (2026-10-17,
   *  `withCredentialBelt`): a commented-out key (`# OLD_STRIPE_KEY=sk_live_…`)
   *  no program reads. Its field row is bound to no host unless a `values:`
   *  entry of the file's label names it (current-bindings.ts), and npm's
   *  wire-twin test passes over it (registry.ts `wireServableTwin`). */
  comment?: true;
  /** A person's NAME in a personal document's twin (2026-10-19,
   *  personal-documents.ts `documentNameField`, secret-discovery.md §2.7):
   *  a placeholder in the twin, its field row minted as any other's, but
   *  no fingerprint of the value backstop or the egress tripwire
   *  (registry.ts `documentNameRows`). Only under DOCUMENT_TWIN_EXTRACT,
   *  never on a span that merged others. */
  name?: true;
}

/** Where a withheld ssh command was: no part of its text. */
export interface WithheldCommand {
  /** The file as the message names it (`~/.ssh/config`), shell-inert. */
  file: string;
  /** 1-based line number in that file. */
  line: number;
  /** `ProxyCommand`, `LocalCommand`, `RemoteCommand`, `KnownHostsCommand`
   *  or `Match exec`. */
  keyword: string;
  /** The span is one word of a `Match` line: the twin double-quotes it. */
  quote?: boolean;
}

export interface SecretExtraction {
  /** Which shape matched (`dotenv`, `ini`, `toml`, `pgpass`, `netrc`,
   *  `npmrc`, `yaml-keys`, `json-keys`, `xml-keys`, `ssh-config`, `pip-conf`,
   *  `git-credentials`, `extract`), or null: whole-file twin. */
  shape: string | null;
  spans: SecretSpan[];
}

export interface ExtractOptions {
  /** A user regex with at least one capturing group; group 1 of every match
   *  is a secret span. Overrides the shape. Invalid ⇒ ignored (whole file). */
  extract?: string;
}

/** Above this the file is not a credential file anyone parses; whole-file twin. */
export const MAX_STRUCTURED_BYTES = 8 * 1024 * 1024;

const NONE: SecretExtraction = { shape: null, spans: [] };

/** Key names that are secrets whatever their value looks like. Deliberately
 *  broad (`KEY`, `AUTH`): a false positive masks a harmless value, a miss
 *  exposes a credential. URL-ish words are NOT here: a URL is judged by
 *  whether it carries a password (see `urlPasswordSpan`). */
const SECRET_KEY_RE =
  /(token|secret|passw|pass\b|pass_|_pass|pwd|api[_-]?key|\bkey\b|_key|key_|auth|credential|private|cert|salt|signing|session_id|cookie)/i;

/** Values a dotenv may keep raw when the key does NOT look secret: integers,
 *  booleans, a plain lowercase word (`production`, `info`, `debug`). Anything
 *  else (mixed case, digits with letters, punctuation) is masked. */
const BENIGN_VALUE_RE = /^(?:\d+|true|false|yes|no|on|off|null|none|[a-z][a-z-]{0,15})$/i;

/** `scheme://user:password@host…` — the password is group 1's offset. */
const URL_USERINFO_RE = /^([a-z][a-z0-9+.-]*:\/\/[^:/@\s]+:)([^@\s]+)@/i;

/** A secret's key: SECRET_KEY_RE, or a name credential-names.ts reads as a
 *  password's or a PIN's (`pw`, `db_pw`, `passphrase`, `passcode`, `pin`,
 *  `card_pin`, `access_code`: 2026-10-19, secret-discovery.md §2.9), which
 *  the regex's substrings miss. */
function isSecretKey(key: string): boolean {
  return SECRET_KEY_RE.test(key) || passwordKind(key) !== null;
}

/** If `value` (at absolute offset `at`) is a URL with a password, the span of
 *  the password only; else null. */
function urlPasswordSpan(key: string, value: string, at: number): SecretSpan | null {
  const m = URL_USERINFO_RE.exec(value);
  if (!m) return null;
  const start = at + m[1]!.length;
  return { key: `${key}.password`, start, end: start + m[2]!.length, value: m[2]! };
}

/** A value's secret span: the password of a URL, else the whole value when the
 *  key looks secret or the value does not look benign, else nothing. */
function valueSpan(key: string, value: string, at: number, alwaysMask: boolean): SecretSpan | null {
  if (value === "") return null;
  if (URL_USERINFO_RE.test(value)) return urlPasswordSpan(key, value, at);
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return null; // a URL with no password: not a secret
  if (!alwaysMask && !isSecretKey(key) && BENIGN_VALUE_RE.test(value)) return null;
  return { key, start: at, end: at + value.length, value };
}

/** Strip matching quotes around an assignment value, returning the inner
 *  offset and text. Trailing `# comment` after an unquoted value is dropped. */
function unquote(raw: string, at: number): { at: number; value: string } {
  let s = raw;
  let off = at;
  // leading whitespace
  const lead = s.match(/^\s*/)![0].length;
  s = s.slice(lead); off += lead;
  if (s.length >= 2 && (s[0] === '"' || s[0] === "'")) {
    const close = s.indexOf(s[0]!, 1);
    if (close > 0) return { at: off + 1, value: s.slice(1, close) };
  }
  // unquoted: cut at the first ` #` comment and trailing whitespace
  const hash = s.search(/\s#/);
  if (hash >= 0) s = s.slice(0, hash);
  s = s.replace(/\s+$/, "");
  return { at: off, value: s };
}

/** A field name longer than this is no configuration anyone writes (a key
 *  path of 2 000 characters): the file is hidden whole instead (NONE, the
 *  fail-safe direction). Past 16 383 characters V8 hashes a string by its
 *  length alone, so the dedupe map of `finish` and `finishMerged` turned
 *  quadratic on many such names: 10 000 `password:` lines under one
 *  20 000-character YAML key (a 156 KB file) took 137 s (2026-10-10), and
 *  `mandu why` runs this on demand from the data socket. */
const MAX_FIELD_NAME = 2048;

/** Deduplicate keys (`KEY`, `KEY__2`, …) and sort spans by offset. NONE
 *  when a field name is longer than `MAX_FIELD_NAME`. */
function finish(shape: string, spans: SecretSpan[]): SecretExtraction {
  if (spans.some((s) => s.key.length > MAX_FIELD_NAME)) return NONE;
  const seen = new Map<string, number>();
  for (const s of spans) {
    const n = (seen.get(s.key) ?? 0) + 1;
    seen.set(s.key, n);
    if (n > 1) s.key = `${s.key}__${n}`;
  }
  spans.sort((a, b) => a.start - b.start);
  // Overlaps cannot happen for line-based shapes; guard the regex override.
  const out: SecretSpan[] = [];
  let last = -1;
  for (const s of spans) {
    if (s.start < last) continue;
    out.push(s);
    last = s.end;
  }
  return { shape, spans: out };
}

/** Walk lines with absolute offsets. */
function* lines(content: string): Generator<{ line: string; at: number }> {
  let at = 0;
  for (const line of content.split("\n")) {
    yield { line: line.endsWith("\r") ? line.slice(0, -1) : line, at };
    at += line.length + 1;
  }
}

// ── shapes ──────────────────────────────────────────────────────────────────

/** One dotenv assignment: `[export ]KEY=value`, `KEY = value`, or node
 *  dotenv's `KEY: value`. The key is node dotenv's grammar (`[\w.-]+`, which
 *  python-dotenv also reads): the narrower `[A-Za-z_]\w*` left `API-KEY=…`
 *  raw in the twin while node loaded it. */
const DOTENV_LINE = /^(\s*(?:export\s+)?)([\w.-]+)(\s*=|:(?=\s|$))(.*)$/;

/** Dotenv lines that are no assignment and hold nothing to mask: the shell's
 *  allexport switch, and a bare `export NAME …` (names are keys, kept raw). */
const DOTENV_INERT = /^\s*(?:set\s+[-+](?:a|o\s+allexport)|export(?:\s+[A-Za-z_][A-Za-z0-9_]*)+)\s*$/;

/**
 * direnv's stdlib built-ins whose arguments are names, paths, layouts or a
 * status message, never a value a loader hands a program (plan 10 §2.4.1,
 * 2026-10-10). In an `.envrc`, a line that calls one of them stays raw in
 * the twin when `direnvBuiltinLine` accepts the rest of it; any other line
 * that is no assignment is masked whole, as before. Left out on purpose:
 * `fetchurl` and `source_url` (a URL is where an access token rides: a
 * signed URL, a token in the path), `direnv_load` (runs a command line),
 * `rvm` (runs rvm with its arguments), and the helpers that only make sense
 * inside a command substitution (`join_args`, `user_rel_path`,
 * `semver_search`), which the line check refuses anyway.
 */
export const DIRENV_BUILTINS: ReadonlySet<string> = new Set([
  "PATH_add", "path_add", "MANPATH_add", "PATH_rm", "path_rm", "load_prefix",
  "layout", "layout_anaconda", "layout_go", "layout_julia", "layout_node", "layout_perl", "layout_php",
  "layout_pipenv", "layout_poetry", "layout_pdm", "layout_pyenv", "layout_python", "layout_python2",
  "layout_python3", "layout_ruby", "layout_uv",
  "use", "use_flake", "use_guix", "use_julia", "use_nix", "use_node", "use_nodenv", "use_rbenv", "use_vim",
  "dotenv", "dotenv_if_exists", "source_env", "source_env_if_exists", "source_up", "source_up_if_exists",
  "watch_file", "watch_dir", "strict_env", "unstrict_env", "env_vars_required",
  "log_status", "log_error", "has", "expand_path", "find_up", "direnv_version", "on_git_branch",
]);

/** The variables a built-in's argument may expand (`PATH_add "$PWD/bin"`):
 *  where the user is, never a value. Any other `$` refuses the line. */
const DIRENV_SAFE_VARS: ReadonlySet<string> = new Set(["PWD", "HOME"]);

/** `$NAME` or `${NAME}` at the start of a text. */
const DIRENV_VAR_RE = /^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/;

/** A character an argument may hold outside quotes: a path, a flake
 *  reference (`.#dev`), a version, a glob. No shell metacharacter: no `;`,
 *  `&`, `|`, `<`, `>`, parentheses, braces, backslash, backquote, `!`. */
const DIRENV_BARE = /^[A-Za-z0-9_./~+@%,:=#*?[\]-]$/;

/** A secret-named flag (`--token`, `--password=…`): what follows it is a
 *  credential whatever its form. */
const DIRENV_SECRET_FLAG = /^--?(?:password|passwd|pass|token|secret|api-?key|auth|pat)(?:$|=)/i;

/**
 * Whether an `.envrc` line that is no assignment is a direnv built-in call
 * that may stay raw in the twin. Fail-closed: every condition must hold.
 *   - The first word is in `DIRENV_BUILTINS`, followed by a blank or the
 *     end of the line.
 *   - The rest is words of `DIRENV_BARE` characters, `'…'` and `"…"` (no
 *     backslash, backquote or control character in either, no `!` in
 *     double quotes), and `$PWD`, `$HOME`, `${PWD}`, `${HOME}` (bare or in
 *     double quotes). A `#` that starts a word starts a comment, to the end
 *     of the line. Anything else refuses: a command substitution, any
 *     other expansion, a redirection, a pipe, `;`, `&&`, a quote never
 *     closed, a line continuation.
 *   - No word, the comment's included, is a URL with a password, a
 *     secret-named flag, a `NAME=` whose name says secret (`isSecretKey`),
 *     or holds a piece `looksLikeSecretValue` takes (pieces split at `/`,
 *     `=`, `#`, `:` and `,`, so a path is judged by its segments); and the
 *     content detector (`locateSecretShapes`) finds no credential format in
 *     the line.
 * Revealing such a line reveals a path (`dotenv .env.local`, `source_env
 * ..`), never what the file at it holds: that file is protected as itself.
 */
export function direnvBuiltinLine(line: string): boolean {
  const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)(?=[ \t]|$)/.exec(line);
  if (!m || !DIRENV_BUILTINS.has(m[1]!)) return false;
  const rest = line.slice(m[0].length);
  const safeVarAt = (text: string, i: number): number => {
    const v = DIRENV_VAR_RE.exec(text.slice(i));
    return v && DIRENV_SAFE_VARS.has((v[1] ?? v[2])!) ? v[0].length : 0;
  };
  const words: string[] = [];
  let word: string | null = null; // the current word, quotes removed
  let i = 0;
  while (i < rest.length) {
    const c = rest[i]!;
    if (c === " " || c === "\t") {
      if (word !== null) words.push(word);
      word = null;
      i++;
    } else if (c === "#" && word === null) {
      words.push(rest.slice(i + 1)); // a comment: its words are judged like the arguments
      break;
    } else if (c === "'" || c === '"') {
      const close = rest.indexOf(c, i + 1);
      if (close < 0) return false;
      const inner = rest.slice(i + 1, close);
      if (/[\\`\x00-\x08\x0a-\x1f\x7f]/.test(inner)) return false;
      if (c === '"') {
        if (inner.includes("!")) return false;
        for (let j = inner.indexOf("$"); j >= 0; j = inner.indexOf("$", j + 1)) if (safeVarAt(inner, j) === 0) return false;
      }
      word = (word ?? "") + inner;
      i = close + 1;
    } else if (c === "$") {
      const n = safeVarAt(rest, i);
      if (n === 0) return false;
      word = (word ?? "") + rest.slice(i, i + n);
      i += n;
    } else if (DIRENV_BARE.test(c)) {
      word = (word ?? "") + c;
      i++;
    } else {
      return false;
    }
  }
  if (word !== null) words.push(word);
  for (const w of words.flatMap((x) => x.split(/\s+/)).filter((x) => x !== "")) {
    if (URL_USERINFO_RE.test(w) || /:\/\/[^/\s]*@/.test(w)) return false;
    if (DIRENV_SECRET_FLAG.test(w)) return false;
    const eq = w.indexOf("=");
    if (eq > 0 && isSecretKey(w.slice(0, eq))) return false;
    // Judged by each piece between `/`, `=`, `#`, `:` and `,`: a path's or
    // a flake reference's pieces are words (`github:NixOS/nixpkgs/nixos-24.05#hello`
    // whole reads as random), while a secret is one long piece, a base64
    // one's `/` aside.
    for (const part of w.split(/[/=#:,]/)) if (part !== "" && looksLikeSecretValue(part)) return false;
  }
  return locateSecretShapes(line).length === 0;
}

/** The offset of the quote that closes the one opening at `open` (a `'`,
 *  `"` or backquote), a backslash escaping the next character as node's and
 *  python's dotenv read it, across lines; -1 if none. */
function closingQuote(content: string, open: number): number {
  const q = content[open]!;
  for (let i = open + 1; i < content.length; i++) {
    const c = content[i];
    if (c === "\\") { i++; continue; }
    if (c === q) return i;
  }
  return -1;
}

/** The end of an unquoted value that starts at `from` on a line whose text
 *  ends at `lineEnd`: before a ` #` comment, trailing whitespace dropped. */
function bareValueEnd(content: string, from: number, lineEnd: number): number {
  const text = content.slice(from, lineEnd);
  const hash = text.search(/\s#/);
  return from + (hash >= 0 ? text.slice(0, hash) : text).replace(/\s+$/, "").length;
}

/**
 * A dotenv (confidentiality-plan-10-flow-taint.md §2.4.1): every
 * assignment's value is classified (`valueSpan`), and every other line that
 * is not blank, a comment or `DOTENV_INERT` is masked whole: fail-closed, a
 * line this parser cannot read may still be one a loader reads. In an
 * `.envrc` (`direnv`), a direnv built-in call `direnvBuiltinLine` accepts
 * (`use nix`, `PATH_add bin`, `dotenv .env.local`) stays raw too.
 *
 * The VALUE REGION of an assignment is what every loader takes as its value:
 *   - a value opening with `'`, `"` or a backquote runs to the quote that
 *     closes it, a backslash escaping the next character (node's and
 *     python's dotenv), ACROSS LINES (both read a multi-line quoted value;
 *     the old line parser left a private key's body raw in the twin), when
 *     only whitespace or a comment follows it on its line;
 *   - otherwise (unquoted, a quote never closed, text after the closing
 *     quote) the rest of the line before a ` #` comment, quotes included.
 *
 * QUOTING: the twin writes a masked value SINGLE-QUOTED,
 * `'<prefix><token><suffix>'`, whatever the file's own quoting. A value the
 * file single-quotes reads exactly as the user wrote it; an unquoted or
 * double-quoted one gains the quotes, because every loader that expands
 * variables (a shell sourcing the file, direnv, docker compose,
 * dotenv-expand, Ruby's and Go's dotenv) expands `$MDU` there, and only
 * single quotes are literal to all of them and to the loaders that expand
 * nothing. `export`, the key, the spacing around `=`, a trailing comment and
 * every other line stay as written. A URL's prefix or suffix that cannot
 * sit inside single quotes (a quote, a backslash, a line break) makes the
 * whole value the span.
 */
function extractDotenv(content: string, direnv = false): SecretExtraction {
  const spans: SecretSpan[] = [];
  let lineNo = 0;
  let at = 0;
  while (at <= content.length) {
    let lineEnd = content.indexOf("\n", at);
    if (lineEnd < 0) lineEnd = content.length;
    const next = lineEnd + 1;
    lineNo++;
    const textEnd = lineEnd > at && content[lineEnd - 1] === "\r" ? lineEnd - 1 : lineEnd;
    const line = content.slice(at, textEnd);
    if (/^\s*(?:#|$)/.test(line) || DOTENV_INERT.test(line)) { at = next; continue; }
    const m = DOTENV_LINE.exec(line);
    if (!m) {
      if (direnv && direnvBuiltinLine(line)) { at = next; continue; }
      // Not an assignment: the whole line, from its first character, is a span.
      const lead = line.match(/^\s*/)![0].length;
      const body = line.slice(lead).replace(/\s+$/, "");
      spans.push({ key: `line${lineNo}`, start: at + lead, end: at + lead + body.length, value: body });
      at = next;
      continue;
    }
    const key = m[2]!;
    const valueAt = at + m[1]!.length + key.length + m[3]!.length;
    const regionStart = valueAt + m[4]!.match(/^\s*/)![0].length;
    const open = content[regionStart];
    let regionEnd = -1;
    let quoted = 0; // 1: the region is a closed quoted value, quotes at both ends
    if (regionStart < textEnd && (open === "'" || open === '"' || open === "`")) {
      const close = closingQuote(content, regionStart);
      if (close > 0) {
        let closeLineEnd = content.indexOf("\n", close);
        if (closeLineEnd < 0) closeLineEnd = content.length;
        if (/^\s*(?:#.*)?\r?$/.test(content.slice(close + 1, closeLineEnd))) {
          regionEnd = close + 1;
          quoted = 1;
        }
      }
    }
    if (regionEnd < 0) regionEnd = bareValueEnd(content, regionStart, textEnd);
    const vAt = regionStart + quoted;
    const value = content.slice(vAt, regionEnd - quoted);
    let s = valueSpan(key, value, vAt, false);
    // A key in a known format the value rules left raw (a URL with no
    // password carrying `?key=sk_live_…`, or one beside the URL's masked
    // password): the whole value, single-quoted like any other (2026-10-17;
    // the credential belt would write the token unquoted, which a shell
    // sourcing the file expands).
    if (locateSecretShapes(value).some((h) => s === null || vAt + h.start < s.start || vAt + h.end > s.end)) {
      s = { key, start: vAt, end: vAt + value.length, value };
    }
    if (s) {
      const prefix = value.slice(0, s.start - vAt);
      const suffix = value.slice(s.end - vAt);
      // A prefix or suffix single quotes cannot hold: the whole value is the span.
      const whole = /['\\\r\n]/.test(prefix + suffix);
      spans.push({
        key: whole ? key : s.key,
        value: whole ? value : s.value,
        start: regionStart,
        end: regionEnd,
        wrap: whole ? { prefix: "", suffix: "" } : { prefix, suffix },
      });
    }
    if (regionEnd > next) {
      // A multi-line value: carry on after the line its closing quote is on.
      const after = content.indexOf("\n", regionEnd);
      lineNo += content.slice(next, after < 0 ? content.length : after).split("\n").length;
      at = after < 0 ? content.length + 1 : after + 1;
    } else {
      at = next;
    }
  }
  return finish("dotenv", spans);
}

const INI_SECTION = /^\s*\[([^\]]+)\]\s*$/;
const INI_LINE = /^(\s*)([A-Za-z_][A-Za-z0-9_.-]*)(\s*[=:]\s*)(.*)$/;

/** INI (`~/.aws/credentials`, `.pypirc`): only secret-looking keys, named
 *  `section.key`. `region = us-east-1` stays raw. */
function extractIni(content: string): SecretExtraction {
  const spans: SecretSpan[] = [];
  let section = "";
  for (const { line, at } of lines(content)) {
    if (/^\s*[#;]/.test(line)) continue;
    const sec = INI_SECTION.exec(line);
    if (sec) { section = sec[1]!.trim(); continue; }
    const m = INI_LINE.exec(line);
    if (!m) continue;
    const key = m[2]!;
    const valueAt = at + m[1]!.length + key.length + m[3]!.length;
    const { at: vAt, value } = unquote(m[4]!, valueAt);
    if (value === "") continue;
    const name = section ? `${section}.${key}` : key;
    const s = isSecretKey(key) ? valueSpan(name, value, vAt, true) : urlPasswordSpan(name, value, vAt);
    if (s) spans.push(s);
  }
  return finish("ini", spans);
}

/** TOML (`~/.cargo/credentials.toml`, wrangler, stripe, snowflake) and
 *  terraform `.tfvars`: the INI reading of `key = "value"` lines, with the
 *  value's quotes kept around the symbol, and the string items of every
 *  array (`args = ["--api-key", "…"]`, one line or several) by
 *  `listItemSpans`. A multi-line string or an inline table cannot be masked
 *  in place without breaking the file, so either one makes the whole file
 *  the twin (the fail-safe direction), as does an array that never closes
 *  or one nested deeper than `MAX_LIST_DEPTH`. */
function extractToml(content: string, extra: (keyed: readonly SecretSpan[]) => SecretSpan[] = () => [], original: string = content): SecretExtraction {
  if (/"""|'''/.test(content)) return NONE;
  if (/^\s*[A-Za-z0-9_.-]+\s*=\s*\{/m.test(content)) return NONE;
  const keyed = extractIni(content).spans;
  const more = extra(keyed);
  if (keyed.length === 0 && more.length === 0) return { shape: "toml", spans: [] }; // whole-file twin, as before
  const lists = tomlLists(content);
  if (lists === null) return NONE; // an array that never closes, or nested past MAX_LIST_DEPTH
  return finishMerged("toml", [...keyed, ...more, ...lists.flatMap((l) => listItemSpans(content, l))], original);
}

/** Codex's `config.toml` (secret-discovery.md §2.10): the generic TOML
 *  reading, with the values of each `[mcp_servers.<name>]` entry
 *  (`mcpEntrySpans`) and the one-line inline tables Codex's own docs use
 *  for them (`env = { K = "v" }`), read in full by mcp-config.ts and
 *  blanked for the generic reader (which twins any file with an inline
 *  table whole). An inline table that reader cannot read, or one outside a
 *  server's table, still makes the whole-file twin. */
function extractCodexToml(content: string): SecretExtraction {
  const reading = codexTomlReading(content);
  if (reading === null) return NONE;
  let blanked = content;
  for (const r of reading.inline) blanked = blanked.slice(0, r.start) + " ".repeat(r.end - r.start) + blanked.slice(r.end);
  return extractToml(blanked, (keyed) => mcpEntrySpans(reading.entries, keyed, "toml"), content);
}

/** Header names whose value is no credential: content negotiation, the
 *  client's name, a protocol or API version. Every other header an MCP
 *  entry sets is masked (it is set by hand to authenticate). */
const BENIGN_HEADER_RE = /^(?:content-type|accept(?:-[a-z-]+)?|user-agent|origin|referer|cache-control|connection|mcp-protocol-version|[a-z0-9-]*-version)$/i;

/** An MCP config's spans less every one whose whole value is a reference
 *  the client expands (`"GITHUB_TOKEN": "${GITHUB_TOKEN}"`, which the key
 *  rule takes for a secret-named key; since 2026-10-22 also OpenCode's
 *  `{env:X}` / `{file:p}`, Continue's `${{ secrets.X }}` and Gemini CLI's
 *  `$X`, mcp-config.ts `mcpWholeReference`): a placeholder there would
 *  replace the reference the server's value comes from with one that
 *  names nothing, and the variable itself is masked where it is set (the
 *  launch's environment masking). A span that merged others is kept. */
function withoutMcpReferences(x: SecretExtraction): SecretExtraction {
  if (x.shape === null || !x.spans.some((s) => s.parts === undefined && mcpWholeReference(s.value))) return x;
  return { ...x, spans: x.spans.filter((s) => s.parts !== undefined || !mcpWholeReference(s.value)) };
}

/**
 * The secret values of MCP server entries (secret-discovery.md §2.10) the
 * key rules missed (`keyed`, the shape's own spans: a value under a
 * secret-looking name, a URL's password), on the file's own text:
 *
 *   - `env`: a value under a secret-looking name, under a name that holds a
 *     header set (`OPENAPI_MCP_HEADERS`, Notion's server), or one that reads
 *     as a credential (`looksLikeSecretValue`) under any name: a server's
 *     environment is where its token goes, whatever the variable is called;
 *   - `headers` / `http_headers`: every value but a benign header's
 *     (`BENIGN_HEADER_RE`): a header a person writes into an MCP config is
 *     there to authenticate;
 *   - `bearer_token` (Codex): the value.
 *
 * Never a reference the client expands (`${…}`, `{env:…}`, `${{ secrets.… }}`,
 * `$VAR`: mcp-config.ts `mcpReference`), an empty value, or a URL (its
 * password is the key rules', its query the credential belt's). Field
 * names: the variable's or header's name (`json-keys`, as the key rules
 * name them), `mcp_servers.<server>.<table>.<name>` (`toml`, as the INI
 * reading does), the value's dotted path (`yaml-keys`, as the YAML key
 * rules name theirs). A value a `keyed` span already covers is left to it.
 * Pure.
 */
function mcpEntrySpans(entries: readonly McpServerEntry[], keyed: readonly SecretSpan[], shape: "json-keys" | "toml" | "yaml-keys"): SecretSpan[] {
  const covered = (a: number, b: number): boolean => keyed.some((s) => s.start < b && a < s.end);
  const out: SecretSpan[] = [];
  for (const e of entries) {
    for (const v of e.values) {
      if (v.raw === "" || mcpReference(v.raw) || covered(v.start, v.end)) continue;
      let secret = false;
      if (v.role === "env") {
        if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v.raw)) continue;
        secret = isSecretKey(v.name) || /HEADERS?$/i.test(v.name) || looksLikeSecretValue(v.raw);
      } else if (v.role === "header") {
        secret = !BENIGN_HEADER_RE.test(v.name);
      } else if (v.role === "bearer") {
        secret = true;
      }
      if (!secret) continue;
      const table = v.role === "env" ? "env" : v.role === "header" ? "http_headers" : "";
      const key = shape === "toml" ? (table === "" ? `mcp_servers.${e.name}.${v.name}` : `mcp_servers.${e.name}.${table}.${v.name}`) : shape === "yaml-keys" ? (v.field ?? v.name) : v.name;
      out.push({ key, start: v.start, end: v.end, value: v.raw });
    }
  }
  return out;
}

/**
 * The wire marks of an MCP config's twin (secret-discovery.md §2.10, plan 10
 * §11.13.1): the credential an HTTP server entry sends in its Authorization
 * header (JSON `headers.Authorization`, Codex `bearer_token` and
 * `http_headers.Authorization`) to the host of the entry's own `url`. A
 * span is marked only when it is exactly that value (a span the belt or a
 * list rule merged with another is never put back); the registration
 * binds it to that host for the launch HOME's own config only
 * (registry.ts `isHomeWireFile`). Runs last, on the returned spans. Pure.
 */
function withMcpWire(path: string, content: string, x: SecretExtraction): SecretExtraction {
  if (x.shape === null || x.spans.length === 0) return x;
  const entries = mcpServerEntries(path, content);
  if (entries === null) return x;
  const marks = new Map<string, NonNullable<SecretSpan["wire"]>>();
  for (const e of entries) {
    if (e.transport !== "http" || e.url === null) continue;
    const host = mcpUrlHost(e.url);
    if (host === null) continue;
    for (const v of e.values) {
      const auth = (v.role === "header" && v.name.toLowerCase() === "authorization") || v.role === "bearer";
      if (auth) marks.set(`${v.start}:${v.end}`, { host: host.host, scheme: "bearer", httpsOnly: host.https });
    }
  }
  if (marks.size === 0) return x;
  let any = false;
  const spans = x.spans.map((s) => {
    const w = marks.get(`${s.start}:${s.end}`);
    if (w === undefined || s.parts !== undefined || s.encoded !== undefined || content.slice(s.start, s.end) !== s.value) return s;
    any = true;
    return { ...s, wire: w };
  });
  return any ? { ...x, spans } : x;
}

/** XML (`~/.m2/settings.xml`, `NuGet.Config`): the text of an element whose
 *  tag looks secret (`<password>…</password>`), the `value` of an
 *  `<add key="…Password" value="…"/>` pair, and an attribute whose own name
 *  looks secret (`password="…"`). */
function extractXmlKeys(content: string): SecretExtraction {
  const spans: SecretSpan[] = [];
  const elem = /<([A-Za-z_][\w.:-]*)(?:\s[^>]*)?>([^<]+)<\/\1>/g;
  let m: RegExpExecArray | null;
  while ((m = elem.exec(content)) !== null) {
    const tag = m[1]!;
    const text = m[2]!;
    if (!isSecretKey(tag) || text.trim() === "") continue;
    const lead = text.length - text.trimStart().length;
    const value = text.trim();
    const start = m.index + m[0].indexOf(">") + 1 + lead;
    spans.push({ key: tag, start, end: start + value.length, value });
  }
  const pair = /<[A-Za-z_][\w.:-]*\s+(?:key|name)="([^"]*)"\s+value="([^"]*)"/g;
  while ((m = pair.exec(content)) !== null) {
    if (!isSecretKey(m[1]!) || m[2] === "") continue;
    const start = m.index + m[0].length - m[2]!.length - 1;
    spans.push({ key: m[1]!, start, end: start + m[2]!.length, value: m[2]! });
  }
  const attr = /\s([A-Za-z_][\w.:-]*)="([^"]*)"/g;
  while ((m = attr.exec(content)) !== null) {
    const name = m[1]!;
    if (name === "key" || name === "name" || !isSecretKey(name) || m[2] === "") continue;
    const start = m.index + m[0].length - m[2]!.length - 1;
    spans.push({ key: name, start, end: start + m[2]!.length, value: m[2]! });
  }
  return finish("xml-keys", spans);
}

/** `.pgpass`: `host:port:db:user:password`, `\:` escapes a colon. */
function extractPgpass(content: string): SecretExtraction {
  const spans: SecretSpan[] = [];
  for (const { line, at } of lines(content)) {
    if (line.trim() === "" || line.startsWith("#")) continue;
    // split on unescaped colons, keeping offsets
    const fields: Array<{ at: number; text: string }> = [];
    let cur = "", curAt = 0;
    for (let i = 0; i < line.length; i++) {
      const c = line[i]!;
      if (c === "\\" && i + 1 < line.length) { cur += c + line[i + 1]; i++; continue; }
      if (c === ":") { fields.push({ at: curAt, text: cur }); cur = ""; curAt = i + 1; continue; }
      cur += c;
    }
    fields.push({ at: curAt, text: cur });
    if (fields.length < 5) continue;
    const pw = fields[fields.length - 1]!;
    if (pw.text === "") continue;
    const user = fields[3]!.text || "user";
    spans.push({ key: `${user}.password`, start: at + pw.at, end: at + pw.at + pw.text.length, value: pw.text });
  }
  return finish("pgpass", spans);
}

/** `.netrc`: the token after `password` (and `passwd`), per machine. */
function extractNetrc(content: string): SecretExtraction {
  const spans: SecretSpan[] = [];
  const re = /\b(machine|default)\s+(\S+)|\b(password|passwd)\s+(\S+)/g;
  let machine = "default";
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    if (m[1] !== undefined) { machine = m[1] === "default" ? "default" : m[2]!; continue; }
    const start = m.index + m[0].length - m[4]!.length;
    spans.push({ key: `${machine}.password`, start, end: start + m[4]!.length, value: m[4]! });
  }
  return finish("netrc", spans);
}

/** `.npmrc`: `//registry/:_authToken=…`, `_auth=…`, `_password=…`.
 *
 *  Plan 10 §11.13.1: a value npm sends in one header to the registry its key
 *  names is marked `wire`, with that registry's host:
 *  `//host[:port]/path/:_authToken` (a Bearer token), `//…/:_auth` (the
 *  stored base64 of `user:password`, sent as Basic as written) and, since
 *  2026-10-03, `//…/:_password` (the base64 of the password, which npm
 *  DECODES and sends inside Basic after the key's `username`): its span is
 *  `encoded: "base64"`, its value the decoded password, and its twin the
 *  base64 of the token, which npm decodes back into the token. A `_password`
 *  that is not clean base64 of printable UTF-8, and any unscoped key (no
 *  registry named), are never marked. The session proxy can put a marked
 *  value back in place of its symbol, so npm can read the twin.
 *
 *  A nerf-dart key names no scheme, so a marked value is `httpsOnly` unless
 *  the file itself declares that host's registry as `http://` (a
 *  `registry=` or `@scope:registry=` line): only then may it be put back
 *  in a plain-HTTP request. */
function extractNpmrc(content: string): SecretExtraction {
  const spans: SecretSpan[] = [];
  const httpHosts = npmrcHttpRegistryHosts(content);
  for (const { line, at } of lines(content)) {
    const m = /^(\s*)((?:\/\/[^=]*?:)?(_authToken|_auth|_password|password|email))(\s*=\s*)(.*)$/.exec(line);
    if (!m || m[3] === "email") continue;
    const valueAt = at + m[1]!.length + m[2]!.length + m[4]!.length;
    const { at: vAt, value } = unquote(m[5]!, valueAt);
    if (value === "") continue;
    const host = m[2]!.startsWith("//") ? m[2]!.slice(2, m[2]!.lastIndexOf("/:")) : "";
    const span: SecretSpan = { key: host ? `${host}.${m[3]}` : m[3]!, start: vAt, end: vAt + value.length, value };
    const registryHost = npmrcRegistryHost(host);
    if (registryHost !== null && (m[3] === "_authToken" || m[3] === "_auth")) {
      span.wire = { host: registryHost, scheme: m[3] === "_authToken" ? "bearer" : "basic", httpsOnly: !httpHosts.has(registryHost) };
    } else if (registryHost !== null && m[3] === "_password") {
      // npm decodes it and sends `Basic base64(username:password)`: the
      // field symbol stands for the decoded password, the twin holds the
      // base64 of the token (§11.13.1, 2026-10-03).
      const plain = decodeBase64Text(value);
      if (plain !== null) {
        span.value = plain;
        span.encoded = "base64";
        span.wire = { host: registryHost, scheme: "basic", httpsOnly: !httpHosts.has(registryHost) };
      }
    }
    spans.push(span);
  }
  return finish("npmrc", spans);
}

/** The hosts (`name[:port]`, lower-cased) an `.npmrc` declares a registry
 *  for over plain `http://` (`registry=http://…`, `@scope:registry=http://…`).
 *  Pure. */
export function npmrcHttpRegistryHosts(content: string): Set<string> {
  const out = new Set<string>();
  for (const { line } of lines(content)) {
    const m = /^\s*(?:@[^\s:=]+:)?registry\s*=\s*["']?(http:\/\/[^\s"']+)/i.exec(line);
    if (!m) continue;
    try {
      const host = npmrcRegistryHost(new URL(m[1]!).host);
      if (host !== null) out.add(host);
    } catch { /* not a URL: declares nothing */ }
  }
  return out;
}

/** The UTF-8 text a canonical base64 string encodes, or null when the
 *  string is not canonical base64 (padding optional) or the text is empty,
 *  not UTF-8, or holds a control character: an npm `_password` the proxy
 *  can put back. Pure. */
export function decodeBase64Text(s: string): string | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  const buf = Buffer.from(s, "base64");
  if (buf.toString("base64").replace(/=+$/, "") !== s.replace(/=+$/, "")) return null;
  const text = buf.toString("utf8");
  if (text === "" || text.includes("�") || /[\u0000-\u001f\u007f]/.test(text)) return null;
  return text;
}

/** Python's `urllib.parse.unquote` (what pip applies to a URL's user and
 *  password): every `%XX` decoded, the bytes read as UTF-8, any other `%`
 *  kept. Null when the decoded bytes are not UTF-8 (Python would put U+FFFD
 *  in their place, a value nobody can put back). Pure. */
export function percentDecodeText(s: string): string | null {
  if (!s.includes("%")) return s;
  const bytes: number[] = [];
  for (let i = 0; i < s.length; ) {
    if (s[i] === "%" && /^[0-9A-Fa-f]{2}$/.test(s.slice(i + 1, i + 3))) {
      bytes.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 3;
      continue;
    }
    const cp = s.codePointAt(i)!;
    const ch = String.fromCodePoint(cp);
    for (const b of Buffer.from(ch, "utf8")) bytes.push(b);
    i += ch.length;
  }
  const text = Buffer.from(bytes).toString("utf8");
  return text.includes("�") ? null : text;
}

/** The host (`name` or `name:port`) of an `.npmrc` nerf-dart key's registry
 *  part (`registry.npmjs.org`, `npm.pkg.github.com/OWNER` → the part before
 *  the first `/`), lower-cased; null when there is none or it is not a plain
 *  host name (no userinfo, no wildcard, no whitespace). Pure. */
export function npmrcRegistryHost(nerfDart: string): string | null {
  const h = nerfDart.split("/", 1)[0]!.toLowerCase();
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$/.test(h)) return null;
  return h;
}

/**
 * The wire host of a pip index URL's authority (after any userinfo): a plain
 * host name or IPv4 address as `npmrcRegistryHost` reads it, or an IPv6
 * literal in brackets (`[2001:db8::1]`, `[::1]:8443`) written in its
 * canonical text (lower case, zeros compressed: `[2001:DB8:0::1]` is
 * `[2001:db8::1]`), the port as a number in 1..65535. Null for anything
 * else, a zone id (`[fe80::1%25eth0]`) and a bare IPv6 address with no
 * brackets included: no wire mark, so nothing is put back (plan 10
 * §11.13.1, 2026-10-17). Pure.
 */
export function indexWireHost(hostport: string): string | null {
  if (!hostport.startsWith("[")) return npmrcRegistryHost(hostport);
  const m = /^\[([0-9A-Fa-f:.]+)\](?::([0-9]{1,5}))?$/.exec(hostport);
  if (!m || isIP(m[1]!) !== 6) return null;
  let canonical: string;
  try {
    canonical = new URL(`http://[${m[1]!}]/`).hostname;
  } catch {
    return null;
  }
  if (m[2] === undefined) return canonical;
  const port = Number(m[2]);
  return port >= 1 && port <= 65535 ? `${canonical}:${port}` : null;
}

/** The `.npmrc` keys that send npm's requests somewhere the session proxy
 *  does not terminate them, or make npm distrust its certificate: a proxy of
 *  the user's own (`proxy`, `https-proxy`, `noproxy`), a CA list that
 *  replaces Node's (`ca`, `cafile`), or a client certificate (`cert`, `key`,
 *  `certfile`, `keyfile`, which TLS inspection cannot present). A file with
 *  any of them is not served as a twin to npm (plan 10 §11.13.1): npm would
 *  send the symbol where nothing puts the token back. Returns the keys found,
 *  in order. Pure. */
export function npmrcProxyBypassKeys(content: string): string[] {
  const out: string[] = [];
  for (const { line } of lines(content)) {
    const m = /^\s*(?:\/\/[^=]*?:)?(proxy|https-proxy|http-proxy|noproxy|no-proxy|cafile|ca|ca\[\]|certfile|keyfile|cert|key)\s*=/.exec(line);
    if (m && !out.includes(m[1]!)) out.push(m[1]!);
  }
  return out;
}

/** YAML, flat `key: value` lines whose key looks secret (`oauth_token:` in
 *  gh's hosts.yml). Nested keys are prefixed by their parents' names. The
 *  string items of every sequence (`- --api-key`, `args: [-y, pkg]`) are
 *  judged by `listItemSpans` (`yamlLists`). */
function extractYamlKeys(content: string, extra: (keyed: readonly SecretSpan[]) => SecretSpan[] = () => []): SecretExtraction {
  const keyed = yamlKeySpans(content);
  // An MCP config's server values (secret-discovery.md §2.10: Goose's,
  // Continue's).
  const more = extra(keyed);
  if (keyed.length === 0 && more.length === 0) return { shape: "yaml-keys", spans: [] }; // whole-file twin, as before
  const lists = yamlLists(content);
  if (lists === null) return NONE; // a flow list that never closes, or nested past MAX_LIST_DEPTH
  const merged = finishMerged("yaml-keys", [...keyed, ...more, ...lists.flatMap((l) => listItemSpans(content, l))], content);
  return { shape: "yaml-keys", spans: quotedPlainFlowItems(content, merged.spans, lists) };
}

/** The key-name spans of a YAML text (`extractYamlKeys`), unchanged since
 *  2026-09-24. */
function yamlKeySpans(content: string): SecretSpan[] {
  const spans: SecretSpan[] = [];
  const stack: Array<{ indent: number; name: string }> = [];
  for (const { line, at } of lines(content)) {
    const m = /^(\s*)(-\s+)?([A-Za-z0-9_.:/-]+)(:\s*)(.*)$/.exec(line);
    if (!m || /^\s*#/.test(line)) continue;
    const indent = m[1]!.length + (m[2]?.length ?? 0);
    while (stack.length && stack[stack.length - 1]!.indent >= indent) stack.pop();
    const key = m[3]!;
    const rawVal = m[5]!;
    if (rawVal === "" || rawVal.startsWith("#")) { stack.push({ indent, name: key }); continue; }
    const valueAt = at + m[1]!.length + (m[2]?.length ?? 0) + key.length + m[4]!.length;
    const { at: vAt, value } = unquote(rawVal, valueAt);
    if (value === "") continue;
    const name = [...stack.map((s) => s.name), key].join(".");
    const s = isSecretKey(key) ? valueSpan(name, value, vAt, true) : urlPasswordSpan(name, value, vAt);
    if (s) spans.push(s);
  }
  return finish("yaml-keys", spans).spans;
}

/** JSON: every `"key": "string"` pair whose key looks secret, at any depth,
 *  and the string items of every array, judged by `listItemSpans`
 *  (`jsonLists`). Pairs are found two ways, and a span either finds is
 *  masked: a flat regex over the text (object nesting is not needed, and
 *  it also finds a pair in a JSONC comment), and the JSON strings as they
 *  are (`jsonStringPairs`). The regex never starts a pair at a quote right
 *  after a backslash (2026-10-10): trying each escaped quote of a long
 *  string scanned the rest of that string again each time (a 64 KB string
 *  of `\"` took 0.7 s, so 8 MB would take hours, and `mandu why` on the
 *  agent's data socket runs this on a file the agent can write). That also
 *  lost, on valid JSON, a pair the old regex found after it had lost track
 *  of the strings (`"C:\\"` ends at a quote after a backslash): the
 *  string walk finds every pair of valid JSON, so the two together find
 *  everything the old regex did (a property test checks it on generated
 *  documents). Both are linear in the text. */
function extractJsonKeys(content: string, extra: (keyed: readonly SecretSpan[]) => SecretSpan[] = () => []): SecretExtraction {
  const spans: SecretSpan[] = [];
  const found = new Set<string>();
  const pair = (key: string, value: string, vAt: number): void => {
    if (value === "") return;
    const s = isSecretKey(key) ? valueSpan(key, value, vAt, true) : urlPasswordSpan(key, value, vAt);
    if (s === null || found.has(`${s.start}:${s.end}`)) return;
    found.add(`${s.start}:${s.end}`);
    spans.push(s);
  };
  const re = /(?<!\\)"((?:[^"\\]|\\.)*)"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) pair(m[1]!, m[2]!, m.index + m[0].length - m[2]!.length - 1);
  for (const p of jsonStringPairs(content)) pair(p.key, p.value, p.at);
  // An MCP config's server values (secret-discovery.md §2.10).
  for (const s of extra(spans)) spans.push(s);
  if (spans.length === 0) return { shape: "json-keys", spans: [] }; // whole-file twin, as before
  // In text order, so a repeated key is numbered as before (`token__2`).
  spans.sort((a, b) => a.start - b.start);
  const lists = jsonLists(content);
  if (lists === null) return NONE; // nested past MAX_LIST_DEPTH
  return finishMerged("json-keys", [...spans, ...lists.flatMap((l) => listItemSpans(content, l))], content);
}

/** Every `"key": "value"` pair of a JSON text as its strings are: a string
 *  that closes on its line, blanks (or a JSONC comment), `:`, blanks, and
 *  a string that closes on its line. The raw text between each one's quotes
 *  (escapes as written, as the regex of `extractJsonKeys` gives them) and
 *  the value's offset. One pass. Pure. */
function jsonStringPairs(content: string): Array<{ key: string; value: string; at: number }> {
  const out: Array<{ key: string; value: string; at: number }> = [];
  // 1: a string was just read (`key`), 2: then a `:`; 0: neither.
  let state = 0;
  let key = "";
  let i = 0;
  while (i < content.length) {
    const c = content[i]!;
    if (c === '"') {
      let j = i + 1;
      let closed = false;
      for (; j < content.length; j++) {
        const d = content[j];
        if (d === "\\") { j++; continue; }
        if (d === '"') { closed = true; break; }
        if (d === "\n" || d === "\r") break;
      }
      const text = content.slice(i + 1, Math.min(j, content.length));
      if (!closed) state = 0;
      else if (state === 2) { out.push({ key, value: text, at: i + 1 }); state = 0; }
      else { key = text; state = 1; }
      i = closed ? j + 1 : j;
    } else if (c === "/" && content[i + 1] === "/") {
      const nl = content.indexOf("\n", i);
      i = nl < 0 ? content.length : nl;
    } else if (c === "/" && content[i + 1] === "*") {
      const close = content.indexOf("*/", i + 2);
      i = close < 0 ? content.length : close + 2;
    } else {
      if (c === ":") state = state === 1 ? 2 : 0;
      else if (!/\s/.test(c)) state = 0;
      i++;
    }
  }
  return out;
}

// ── list items (2026-10-09) ─────────────────────────────────────────────────
//
// A string item of a list has no key of its own, so the key-name rule
// above cannot judge it. The three structured shapes that have lists (JSON
// arrays, YAML sequences, TOML arrays) each find their lists and decode
// their string items (`jsonLists`, `yamlLists`, `tomlLists`); one rule set
// (`listItemSpans`) decides which part of an item is a secret. Spans are on
// the file's own text (an escaped character is masked with its escape), so
// the twin stays parseable: a field token needs no escaping in any of the
// three quote styles.
//
// List items only ADD to a file whose keys already gave a secret span. A
// file with none stays the whole-file twin, as before: these shapes are not
// exhaustive, so a structured twin shows every value no rule recognizes,
// and list items alone must not turn a file hidden whole into one that
// shows more (a labelled `.mcp.json` whose only secret is a URL in `args`).

/** One string item of a list: its text as the program reads it (escapes
 *  decoded, quotes removed), and `at[i]`, the file offset of the text's
 *  i-th character (`at[text.length]` is the offset just past the last). */
interface ListItem {
  text: string;
  at: number[];
  /** A YAML plain (unquoted) item of a flow sequence (`[-y, pkg]`): a
   *  placeholder in it must be quoted (`quotedPlainFlowItems`). */
  flowPlain?: boolean;
}

/** Lists nested deeper than this (a list in a list in …; for JSON, objects
 *  and arrays together) are no configuration anyone writes. Such a file is
 *  hidden whole: field names stay short and no walk recurses that deep (a
 *  YAML or TOML `[[[[…` 100 000 deep overflowed the stack, 2026-10-10). */
const MAX_LIST_DEPTH = 64;

/** A list's field-name prefix longer than this (keys nested past any real
 *  configuration) hides the file whole too: every masked item's field name
 *  repeats it, so a deep path times many items would cost memory out of
 *  all proportion to the file. */
const MAX_LIST_NAME = 1024;

/** A list found in a structured file. */
interface ListGroup {
  /** Field-name prefix of its items (`args`, `servers.brave.args`). */
  name: string;
  /** The list sits under a key that looks secret (`"api_keys": [...]`). */
  secretKey: boolean;
  /** Its items in order; a non-string item (a number, an object, a nested
   *  list) is null and keeps its place, so item i is the list's i-th. */
  items: Array<ListItem | null>;
  /** The `command` string of the object, mapping or table the list sits
   *  in, if any: a program whose one-letter flag takes a password. */
  command?: string;
}

/** The last word of a flag or header name that says it takes a secret:
 *  `--api-key`, `--token`, `--db-password`, `--client-secret`, Go's
 *  single-dash `-password`, `X-API-Key`; `--auth`, `--basic-auth`,
 *  `--http-auth`, `--proxy-auth` and `--pat` (a personal access token)
 *  since 2026-10-10. Not `--author`, `--oauth` or `--path`: the last word
 *  must be one of these exactly. */
const SECRET_FLAG_WORDS: ReadonlySet<string> = new Set([
  "password", "passwd", "pass", "pw", "pwd", "passphrase", "secret", "token", "key", "apikey", "bearer", "credential", "credentials", "cookie",
  "auth", "pat",
]);

/** The programs whose `-u` / `--user` is `uid:gid` or `user:group`, not a
 *  password (`docker run -u 1000:1000`), when one of them is the command
 *  itself (`CommandContext.isCommand`) and no other program is named after
 *  it before the flag. Anywhere else `-u`,
 *  `--user` and `--proxy-user` (and curl's `-U`) take `user:password`: only
 *  the password is masked, or the user when the password is empty (`-u
 *  KEY:`, the form an API that takes its key as the user name documents). */
const UID_GID_USER_PROGRAMS: ReadonlySet<string> = new Set(["docker", "podman", "nerdctl", "buildah", "finch"]);

/** httpie's programs: `-a` and `--auth` take the credential (`-a
 *  user:password`: the password is masked; a token with `-A bearer`: the
 *  whole value). */
const HTTPIE_PROGRAMS: ReadonlySet<string> = new Set(["http", "https", "xh", "xhs", "httpie"]);

/** The programs whose `login` takes the password as `-p` (`docker login -u
 *  me -p …`, `helm registry login -p …`, `az login -p …`); outside `login`
 *  their `-p` is a port or something else. Not `gh`, whose `auth login -p`
 *  names a git protocol. */
const LOGIN_PASSWORD_PROGRAMS: ReadonlySet<string> = new Set([...UID_GID_USER_PROGRAMS, "skopeo", "oras", "helm", "az", "cf", "oc"]);

/** The programs whose `--password` takes no next word: psql and the other
 *  PostgreSQL clients (a switch: ask for it) and mysql and its tools (a
 *  value only after `=`, `--password=…`; alone it asks, and the next word
 *  is the database). Only when one of them is the command itself
 *  (`CommandContext.isCommand`): a word that merely names one (a path
 *  `/var/lib/mysql`, an image `mcp/mysql`, a value `--db-type mysql`) says
 *  nothing about whose `--password` follows, and it takes its value. */
const PROMPTED_PASSWORD_PROGRAMS: ReadonlySet<string> = new Set([
  "psql", "pg_dump", "pg_dumpall", "pg_restore", "pg_basebackup", "createdb", "dropdb", "createuser", "dropuser", "vacuumdb", "reindexdb",
  "clusterdb", "pgbench", "mysql", "mysqldump", "mysqladmin", "mariadb", "mariadb-dump", "mysqlimport", "mysqlshow", "mysqlcheck",
]);

/** A double-dash flag's name may also END in one of these, glued to the
 *  word before it (`--accesstoken`, `--dbpassword`, `--secretkey`; not
 *  `--hotkey` or `--monkey`). */
const SECRET_FLAG_SUFFIX_RE = /(?:password|passwd|passphrase|secret|token|apikey|secretkey|privatekey|accesskey)$/;

/** A first word that makes a flag ending in `auth` a switch, not a flag
 *  that takes a credential (`--skip-auth`, `--disable-basic-auth`,
 *  `--require-auth`; `--no-auth` is a negation already), and a word before
 *  `pat` that makes it a pattern (`--exclude-pat`, `--include-pat`), not a
 *  personal access token (2026-10-10). Both over-masked before, the safe
 *  direction: these are the common forms, pinned by a unit test, and
 *  `--auth`, `--basic-auth`, `--pat` and `--gitlab-pat` still take one. */
const AUTH_SWITCH_WORDS: ReadonlySet<string> = new Set(["skip", "disable", "enable", "without", "require", "bypass", "ignore", "allow", "insecure"]);
const PATTERN_PAT_WORDS: ReadonlySet<string> = new Set(["exclude", "include", "ignore", "match", "filter", "glob", "file", "name", "path", "search", "select", "grep", "regex", "skip", "only"]);

/** A first word that makes any secret-named flag a switch that asks for the
 *  secret instead of taking it (`--ask-password` of wget, `--ask-pass` and
 *  `--ask-vault-pass` of ansible), 2026-10-10 (third review). */
const ASK_SWITCH_WORDS: ReadonlySet<string> = new Set(["ask", "prompt"]);

/** Is `name` (a flag name without its dashes, or a header name) one that
 *  takes a secret? By its LAST word (split at `-`, `_`, `.`), so a file or
 *  path flag (`--key-file`, `--token-path`, `--password-stdin`) and a
 *  negation (`--no-password`) are not, nor a switch or pattern flag of
 *  `AUTH_SWITCH_WORDS`, `PATTERN_PAT_WORDS` and `ASK_SWITCH_WORDS`.
 *  `glued`: a double-dash name may also end in a secret word
 *  (`--authtoken`). Pure. */
function secretFlagName(name: string, glued: boolean): boolean {
  const words = name.toLowerCase().split(/[-_.]+/).filter((w) => w !== "");
  if (words.length === 0 || words[0] === "no") return false;
  if (words.length > 1 && ASK_SWITCH_WORDS.has(words[0]!)) return false;
  const last = words[words.length - 1]!;
  if (words.length > 1 && last === "auth" && AUTH_SWITCH_WORDS.has(words[0]!)) return false;
  if (words.length > 1 && last === "pat" && PATTERN_PAT_WORDS.has(words[words.length - 2]!)) return false;
  return SECRET_FLAG_WORDS.has(last) || (glued && SECRET_FLAG_SUFFIX_RE.test(last));
}

/** The programs whose ONE-LETTER flag takes a password (`separate`: as the
 *  next word too, not only glued). Elsewhere a one-letter flag is no secret
 *  flag: `-p` is a port to docker (`-p 8080:80`) and ssh, a package to npx
 *  and a Python to uv. `mysql -p db` prompts and names a database, so
 *  mysql's `-p` counts only glued (`-ppw`). */
const PASSWORD_LETTER_FLAGS: Readonly<Record<string, { letter: string; separate: boolean }>> = {
  sshpass: { letter: "p", separate: true },
  mysql: { letter: "p", separate: false },
  mysqldump: { letter: "p", separate: false },
  mysqladmin: { letter: "p", separate: false },
  mariadb: { letter: "p", separate: false },
  "mariadb-dump": { letter: "p", separate: false },
  "redis-cli": { letter: "a", separate: true },
};

/** Every program a word may name that changes how a flag after it reads
 *  (the tables above, curl's `-U` and `-b`, gh's `secret set --body`). The
 *  last one named in a command is its `CommandContext.program`; whether
 *  the command word named it is `CommandContext.isCommand`. */
const KNOWN_PROGRAMS: ReadonlySet<string> = new Set([
  ...UID_GID_USER_PROGRAMS, ...HTTPIE_PROGRAMS, ...LOGIN_PASSWORD_PROGRAMS, ...PROMPTED_PASSWORD_PROGRAMS, ...Object.keys(PASSWORD_LETTER_FLAGS),
  "curl", "wget", "gh",
]);

/** The program `word` names, by its basename in lower case, if one of
 *  `KNOWN_PROGRAMS`; null for anything else, a URL or an assignment. */
function programOf(word: string): string | null {
  if (/[\s:=@]/.test(word)) return null;
  const base = word.split(/[/\\]/).pop()!.toLowerCase().replace(/\.exe$/, "");
  return KNOWN_PROGRAMS.has(base) ? base : null;
}

/**
 * A program or shell word that runs the command after it (`sudo -u postgres
 * psql`, `env PGPASSWORD=… psql`, `timeout 30 psql`, `then psql`): the word
 * after its options is the command word (`commandSlot`), 2026-10-10 (fourth
 * review). Each lists the options it has: `arg`, letters that take the next
 * word unless a value is glued (`-u postgres`, `-upostgres`); `flag`,
 * letters that take none; `optional`, letters whose value is only glued
 * (`xargs -i{}`); `longArg` and `longFlag` the same for `--name` (any
 * `--name=value` of either is one word); `positional`, words that are no
 * option before the command (timeout's duration); `numeric`, `-10` is an
 * option (nice); `dash`, a lone `-` is one (env). Any other option ends the
 * search for this command: then it has no command word, and no program
 * narrows a flag (`sudo -h host …`, `env -S '…'`, `command -v psql`), the
 * safe way. The table must be right about which options take a value: one
 * listed as taking none whose value were `mysql` would make that value the
 * command word (each entry is from the program's own manual).
 */
interface Wrapper {
  arg?: string;
  flag?: string;
  optional?: string;
  longArg?: readonly string[];
  longFlag?: readonly string[];
  positional?: number;
  numeric?: boolean;
  dash?: boolean;
}

const WRAPPERS: ReadonlyMap<string, Wrapper> = new Map<string, Wrapper>([
  ["sudo", {
    arg: "CDgpRrTtUu", flag: "AbBEHiKknNPSs",
    longArg: ["chdir", "chroot", "close-from", "command-timeout", "group", "host", "other-user", "prompt", "role", "type", "user"],
    longFlag: ["askpass", "background", "bell", "login", "no-update", "non-interactive", "preserve-env", "preserve-groups", "remove-timestamp", "reset-timestamp", "set-home", "shell", "stdin"],
  }],
  ["doas", { arg: "u", flag: "n" }],
  ["env", {
    arg: "uCP", flag: "i0v", dash: true, longArg: ["unset", "chdir"],
    longFlag: ["ignore-environment", "null", "debug", "block-signal", "default-signal", "ignore-signal", "list-signal-handling"],
  }],
  ["nice", { arg: "n", longArg: ["adjustment"], numeric: true }],
  ["nohup", {}],
  ["timeout", { arg: "ks", flag: "v", longArg: ["kill-after", "signal"], longFlag: ["preserve-status", "foreground", "verbose"], positional: 1 }],
  ["exec", { arg: "a", flag: "cl" }],
  ["command", { flag: "p" }],
  ["xargs", {
    arg: "adEILnPs", flag: "0rtpxo", optional: "eil",
    longArg: ["arg-file", "delimiter", "max-args", "max-procs", "max-chars", "process-slot-var"],
    longFlag: ["null", "no-run-if-empty", "verbose", "interactive", "exit", "open-tty", "show-limits", "eof", "replace", "max-lines"],
  }],
  ["time", { arg: "fo", flag: "apqv", longArg: ["format", "output"], longFlag: ["append", "portability", "quiet", "verbose"] }],
  ["stdbuf", { arg: "ioe", longArg: ["input", "output", "error"] }],
  ["ionice", { arg: "cn", flag: "t", longArg: ["class", "classdata"], longFlag: ["ignore"] }],
  ["setsid", { flag: "cfw", longFlag: ["ctty", "fork", "wait"] }],
  // Shell words before a command.
  ...["!", "{", "if", "then", "elif", "else", "do", "while", "until"].map((k): [string, Wrapper] => [k, {}]),
]);

/** A wrapper's option word `s`: `none` (it takes no next word), `arg` (the
 *  next word is its value) or null (an option Mandu does not know). */
function wrapperOption(wr: Wrapper, s: string): "none" | "arg" | null {
  if (s.startsWith("--")) {
    const eq = s.indexOf("=");
    const name = s.slice(2, eq < 0 ? s.length : eq);
    if (wr.longArg?.includes(name)) return eq < 0 ? "arg" : "none";
    return wr.longFlag?.includes(name) ? "none" : null;
  }
  if (s === "-") return wr.dash === true ? "none" : null;
  if (wr.numeric === true && /^-\d+$/.test(s)) return "none";
  for (let j = 1; j < s.length; j++) {
    const c = s[j]!;
    if (wr.arg?.includes(c)) return j + 1 < s.length ? "none" : "arg";
    if (wr.optional?.includes(c)) return "none";
    if (!(wr.flag?.includes(c) ?? false)) return null;
  }
  return "none";
}

/** A shell assignment before a command (`PGPASSWORD=… psql`). */
const COMMAND_ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * Where `s`, the next word of a command, stands (2026-10-10, fourth
 * review): true when it is the command word, the program the command runs.
 * That is the first word of a command (`slot` `start`: a script's first
 * word, the word after a shell operator that starts a command, the list's
 * `command`) past any `NAME=value` and any `WRAPPERS` word with its
 * options. Moves `ctx.slot`. A word that starts with `-` where the command
 * word would be ends the search (`args`): the command has none.
 */
function commandSlot(ctx: CommandContext, s: string): boolean {
  if (ctx.slot === "args") return false;
  if (ctx.slot === "optionArg") {
    ctx.slot = "options";
    return false;
  }
  if (ctx.slot === "options") {
    const wr = ctx.wrapper!;
    if (s === "--") {
      ctx.slot = ctx.positional > 0 ? "positional" : "start";
      return false;
    }
    if (s.startsWith("-") && s.length > 1 || s === "-" && wr.dash === true) {
      const o = wrapperOption(wr, s);
      ctx.slot = o === null ? "args" : o === "arg" ? "optionArg" : "options";
      return false;
    }
    ctx.slot = "positional";
  }
  if (ctx.slot === "positional") {
    if (ctx.positional > 0) {
      ctx.positional--;
      if (ctx.positional === 0) ctx.slot = "start";
      return false;
    }
    ctx.slot = "start";
  }
  if (COMMAND_ASSIGNMENT_RE.test(s)) return false;
  if (s.startsWith("-")) {
    ctx.slot = "args";
    return false;
  }
  const wr = WRAPPERS.get(s.split(/[/\\]/).pop()!);
  if (wr !== undefined) {
    [ctx.wrapper, ctx.positional, ctx.slot] = [wr, wr.positional ?? 0, "options"];
    return false;
  }
  ctx.slot = "args";
  return true;
}

/** A value that is wholly a reference the program or the agent resolves
 *  (`${API_KEY}`, `$API_KEY`, VS Code's `${input:token}`, `${env:X}`), not
 *  a secret, when something resolves it (`referenceValue`). A default
 *  after it (`${X:-value}`) is not a reference. */
const TEMPLATE_REFERENCE_RE = /^\$(?:\{[A-Za-z_][A-Za-z0-9_]*(?::[A-Za-z_][A-Za-z0-9_.-]*)?\}|[A-Za-z_][A-Za-z0-9_]*)$/;

/** A `${…}` reference: the form an MCP client expands in a config (Claude
 *  Code's `${VAR}`, VS Code's and Cursor's `${input:…}` and `${env:…}`). */
function bracedReference(v: string): boolean {
  return v[1] === "{" && TEMPLATE_REFERENCE_RE.test(v);
}

/**
 * Every URL with a password inside a text (`scheme://user:password@`), as
 * the password's [start, end): what
 * `/(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s@]+)@/gi`
 * finds, in linear time (2026-10-10). That regex tried every `x://u:` start
 * of a list item and scanned the rest of the item for an `@` each time (a
 * 256 KB item took 9.7 s, an 8 MB one would take hours, on a file the agent
 * can write). A URL with a password holds no blank and no `@` before its
 * `@`, so each `@` looks back only over its own run of such characters, and
 * the runs do not overlap. Pure.
 */
function urlPasswordsIn(t: string): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  let run = 0;
  for (let p = 0; p < t.length; p++) {
    const c = t[p]!;
    if (c === "@") {
      const pw = urlPasswordBefore(t, run, p);
      if (pw !== null) out.push(pw);
      run = p + 1;
    } else if (/\s/.test(c)) {
      run = p + 1;
    }
  }
  return out;
}

/** In `t[s, p)` (no blank, no `@`; `t[p]` is `@`), the password of the
 *  leftmost `scheme://user:` whose password runs to `p`, as the regex of
 *  `urlPasswordsIn` reads it: a scheme starts with a letter and no scheme
 *  character comes before it, the user is not empty and holds no `:` or
 *  `/`, the password is not empty. Each character is looked at a bounded
 *  number of times. Pure. */
function urlPasswordBefore(t: string, s: number, p: number): [number, number] | null {
  for (let i = s; i + 2 < p; i++) {
    if (t[i] !== ":" || t[i + 1] !== "/" || t[i + 2] !== "/") continue;
    let a = i;
    while (a > s && /[A-Za-z0-9+.-]/.test(t[a - 1]!)) a--;
    if (a === i || !/[A-Za-z]/.test(t[a]!)) continue;
    let u = i + 3;
    while (u < p && t[u] !== ":" && t[u] !== "/") u++;
    if (u === i + 3 || u >= p - 1 || t[u] !== ":") continue;
    return [u + 1, p];
  }
  return null;
}

/** An `Authorization` value's scheme word, kept raw before the credential;
 *  the same word alone (`-H Authorization: Bearer X` unquoted, three words). */
const AUTH_SCHEME_RE = /^(?:bearer|basic|token|bot|digest|apikey|key)\s+/i;
const AUTH_SCHEME_WORD_RE = /^(?:bearer|basic|token|bot|digest|apikey|key)$/i;

/** A header at the start of a word or value (sticky: from `lastIndex`):
 *  `Name:` and the blanks after it; not httpie's `name:=value`. */
const HEADER_AT_RE = /([A-Za-z][A-Za-z0-9-]*):(?!=)[ \t]*/y;

/** `NAME=VALUE` at the start of a word (sticky), and httpie's `NAME:=VALUE`
 *  (raw JSON) and `NAME==VALUE` (a query parameter). A NAME may hold `/`,
 *  `:`, `@` and `.`, so npm's `//registry.npmjs.org/:_authToken=…` is one. */
const ASSIGNMENT_AT_RE = /([A-Za-z_/@.][A-Za-z0-9_./:@-]*?)(?::=|==|=)/y;

/** How deep a command line inside a word is read: an item (1), a quoted
 *  word in it such as `sh -c "…"`'s script (2), one more inside that (3). */
const MAX_COMMAND_DEPTH = 3;

/** One word of a command line: an item of a list (as a program's argv gets
 *  it), or a shell word of the text of one (`commandWords`). */
interface CommandWord {
  /** Its text: an item's as written, a shell word's with quotes and escapes removed. */
  text: string;
  /** The list item it is in. */
  item: number;
  /** The index in that item's text of each character of `text`; null: the
   *  item itself (character i at i), as the program gets it: no shell
   *  reads it. */
  idx: number[] | null;
  /** A shell operator (`;`, `&&`, `|`, `<`, a newline, …) stands before
   *  it: the command's context ends, and a flag takes no value across it. */
  afterOperator: boolean;
  /** The last operator before it starts a command (`;`, `&`, `&&`, `|`,
   *  `||`, `(`, `$(`, an opening backquote, a newline), so it may be a
   *  command word; not `<`, `>`, `>&`, `)` or a closing backquote. */
  commandStart?: boolean;
  /** The indexes in `text` of each `$` the shell keeps as it is (in single
   *  quotes, or escaped): it starts no reference. */
  literal?: ReadonlySet<number> | null;
}

/** What the words before a flag in its command say about it. */
interface CommandContext {
  /** The `KNOWN_PROGRAMS` program named last (`programOf`), if any. */
  program: string | null;
  /**
   * `program` is the command itself: the command word named it
   * (`commandSlot`) and no other program was named since (2026-10-10,
   * fourth review). Only then do the rules that make Mandu mask LESS
   * hold: `--password` after `PROMPTED_PASSWORD_PROGRAMS` takes no next
   * word, `-u` / `--user` after `UID_GID_USER_PROGRAMS` is a user and
   * group, and a program's letter is read before a Go-style name (`mysql
   * -pass`). A word that only names a program (`/var/lib/mysql`, the
   * image `mcp/mysql`, the value of `--db-type mysql`) sets `program` for
   * the rules that make Mandu mask MORE (curl's `-U`, `docker login -p`).
   */
  isCommand: boolean;
  /** Where the next word stands (`commandSlot`): `start`, the command word
   *  is still to come (past `NAME=` and wrappers); `options` and
   *  `optionArg`, a wrapper's options and an option's value; `positional`,
   *  a wrapper's words before the command; `args`, past the command word,
   *  or there is none. */
  slot: "start" | "options" | "optionArg" | "positional" | "args";
  /** The wrapper whose options are being read. */
  wrapper: Wrapper | null;
  /** The wrapper's positional words still to come. */
  positional: number;
  /** `login` was named after it (`docker login`). */
  login: boolean;
  /** `secret` was named after `gh` (`gh secret set NAME --body …`). */
  ghSecret: boolean;
  /** The plain word before, in lower case (`config set <key> <value>`). */
  prev: string | null;
}

/** A context: `start`, at a command's first word (a script), or `args`,
 *  inside a command whose command word is elsewhere or unknown. */
function newContext(slot: "start" | "args"): CommandContext {
  return { program: null, isCommand: false, slot, wrapper: null, positional: 0, login: false, ghSecret: false, prev: null };
}

/** A list's context: `command`, the `command` string beside it (an MCP
 *  server's), is the command, read word by word as a command's first
 *  words (`sudo -u postgres` leaves the list's first item to be the
 *  command word). With no `command`, no item is the command word: the
 *  list may be a program's arguments (`args` beside a Kubernetes
 *  `command` list), so its first item says nothing about whose flags
 *  follow. */
function listContext(command: string | undefined): CommandContext {
  const ctx = newContext(command === undefined ? "args" : "start");
  for (const word of command?.trim().split(/\s+/) ?? []) {
    if (word !== "") wordContext(ctx, word, commandSlot(ctx, word));
  }
  return ctx;
}

/** What plain word `s` says for the words after it: a program it names
 *  (`command`: it is the command word, so a word naming no program names
 *  none for the command), `login`, `gh secret`, and the word before. */
function wordContext(ctx: CommandContext, s: string, command: boolean): void {
  const p = programOf(s);
  if (command) [ctx.program, ctx.isCommand, ctx.login, ctx.ghSecret] = [p, p !== null, false, false];
  else if (p !== null) [ctx.program, ctx.isCommand, ctx.login, ctx.ghSecret] = [p, false, false, false];
  else if (s === "login") ctx.login = true;
  else if (s === "secret" && ctx.program === "gh") ctx.ghSecret = true;
  ctx.prev = s.toLowerCase();
}

/** A shell operator ends the command's context: `start` when it starts a
 *  new command (`w.commandStart`). */
function operatorContext(ctx: CommandContext, w: CommandWord): void {
  [ctx.program, ctx.isCommand, ctx.login, ctx.ghSecret, ctx.prev] = [null, false, false, false, null];
  [ctx.slot, ctx.wrapper, ctx.positional] = [w.commandStart === true ? "start" : "args", null, 0];
}

const SHELL_OPERATOR_CHARS: ReadonlySet<string> = new Set([";", "|", "&", "<", ">", "(", ")", "`", "\n", "\r"]);

/**
 * The shell words of `text` (2026-10-10, third review): blanks separate
 * words; `'…'` is literal; in `"…"` a backslash escapes `"`, `\`, `$` and a
 * backquote; outside quotes a backslash escapes the next character; a quote
 * that never closes runs to the end; `; | & < > ( )`, `$(`, a backquote
 * and a newline end a word and the command's context (`afterOperator`), so
 * `--token $(cat f)` takes no value and `cat f` is read as a command. Of
 * those, `; | & ( $(`, an opening backquote and a newline start a command
 * (`commandStart`, fourth review): the word after `>`, `>&`, `)` or a
 * closing backquote is a file, a descriptor or the rest of the word, never
 * a command word. A `$` in single quotes or escaped is `literal`. Each
 * character keeps its index in the item's text (`idx`: the item's own
 * index of `text[i]`, or i). One pass, linear. Pure.
 */
function commandWords(text: string, item: number, idx: readonly number[] | null): CommandWord[] {
  const st: WordsState = { text, item, idx, words: [], word: "", at: [], lit: [], started: false, afterOperator: false, commandStart: false, backquote: false };
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === " " || c === "\t" || c === "\f" || c === "\v") {
      endWord(st);
    } else if (c === "$" && text[i + 1] === "(") {
      // A command substitution: its command is read as words of its own.
      endWord(st);
      [st.afterOperator, st.commandStart] = [true, true];
      i++;
    } else if (SHELL_OPERATOR_CHARS.has(c)) {
      endWord(st);
      [st.afterOperator, st.commandStart] = [true, operatorStartsCommand(st, i)];
    } else if (c === "'") {
      st.started = true;
      const close = text.indexOf("'", i + 1);
      const stop = close < 0 ? text.length : close;
      for (let j = i + 1; j < stop; j++) addChar(st, j, text[j] === "$");
      i = stop;
    } else if (c === '"') {
      st.started = true;
      let j = i + 1;
      for (; j < text.length && text[j] !== '"'; j++) {
        const escaped = text[j] === "\\" && j + 1 < text.length && '"\\$`'.includes(text[j + 1]!);
        if (escaped) j++;
        addChar(st, j, escaped && text[j] === "$");
      }
      i = j;
    } else if (c === "\\" && i + 1 < text.length) {
      i++;
      if (text[i] !== "\n") addChar(st, i, text[i] === "$");
    } else {
      addChar(st, i, false);
    }
  }
  endWord(st);
  return st.words;
}

/** Does the operator character at i start a command? `<`, `>` and `)` do
 *  not, nor `&` or `|` right after `<` or `>` (`2>&1`, `>|`); a backquote
 *  does when it opens. */
function operatorStartsCommand(st: WordsState, i: number): boolean {
  const c = st.text[i]!;
  if (c === "<" || c === ">" || c === ")") return false;
  if (c === "&" || c === "|") return !(i > 0 && (st.text[i - 1] === "<" || st.text[i - 1] === ">"));
  if (c === "`") st.backquote = !st.backquote;
  return c !== "`" || st.backquote;
}

/** `commandWords` as it goes (module functions, no closures: see `ListReader`). */
interface WordsState {
  text: string;
  item: number;
  idx: readonly number[] | null;
  words: CommandWord[];
  word: string;
  at: number[];
  /** The indexes in `word` of its literal `$`s. */
  lit: number[];
  started: boolean;
  afterOperator: boolean;
  commandStart: boolean;
  /** Inside a backquote command substitution. */
  backquote: boolean;
}

/** Character j of the text joins the word being read; `literal`: it is a
 *  `$` the shell keeps as it is. */
function addChar(st: WordsState, j: number, literal: boolean): void {
  st.started = true;
  if (literal) st.lit.push(st.word.length);
  st.word += st.text[j];
  st.at.push(st.idx === null ? j : st.idx[j]!);
}

/** The word being read, if any, is done. */
function endWord(st: WordsState): void {
  if (!st.started) return;
  const literal = st.lit.length > 0 ? new Set(st.lit) : null;
  st.words.push({ text: st.word, item: st.item, idx: st.at, afterOperator: st.afterOperator, commandStart: st.commandStart, literal });
  st.word = "";
  st.at = [];
  st.lit = [];
  st.started = false;
  st.afterOperator = false;
  st.commandStart = false;
}

/** A flag's value as Mandu judges it: `whole` (`valueSpan`: a URL keeps
 *  all but its password), `user` (`user:password`: the password; nothing
 *  for a bare user), `credential` (httpie's `-a`: `user:password` as
 *  `user` does, any other value whole: a token) or `header` (`Name:
 *  value`: the value of a secret-named header). */
type FlagKind = "whole" | "user" | "credential" | "header";

/** A flag that takes a secret, and whether it takes the next word too
 *  (`separate`) or only a glued or `=` value. */
interface SecretFlag { kind: FlagKind; separate: boolean }

/** `-u` / `--user` is a user and group here: a `UID_GID_USER_PROGRAMS`
 *  program is the command itself (`isCommand`). */
function uidUser(ctx: CommandContext): boolean {
  return ctx.isCommand && ctx.program !== null && UID_GID_USER_PROGRAMS.has(ctx.program);
}

/** Is `name` (a `--name`'s, in any case) a flag that takes a secret here?
 *  `--user`, `--proxy-user` (`user`); `--header`, `--proxy-header`
 *  (`header`); gh's `--body` after `gh secret`; any `secretFlagName`, the
 *  name's `/`, `:` and `@` read as word breaks (npm's
 *  `--//registry.npmjs.org/:_authToken=…`), taking no next word as
 *  `--password` of a `PROMPTED_PASSWORD_PROGRAMS` program that is the
 *  command itself (`isCommand`). */
function longSecretFlag(name: string, ctx: CommandContext): SecretFlag | null {
  const n = name.toLowerCase();
  if (n === "user" || n === "proxy-user") return uidUser(ctx) ? null : { kind: "user", separate: true };
  if (n === "header" || n === "proxy-header") return { kind: "header", separate: true };
  if (n === "body" && ctx.ghSecret) return { kind: "whole", separate: true };
  if (n === "auth" && ctx.program !== null && HTTPIE_PROGRAMS.has(ctx.program)) return { kind: "credential", separate: true };
  if (!secretFlagName(n.replace(/[:/@]+/g, "-"), true)) return null;
  const prompted = n === "password" && ctx.isCommand && ctx.program !== null && PROMPTED_PASSWORD_PROGRAMS.has(ctx.program);
  return { kind: "whole", separate: !prompted };
}

/** Is the one-letter flag `c` one that takes a secret here? `-u` (not
 *  after a `UID_GID_USER_PROGRAMS` program), curl's `-U`: `user`; `-H`:
 *  `header`; a `PASSWORD_LETTER_FLAGS` letter of the program; `-p` after
 *  `login` of a `LOGIN_PASSWORD_PROGRAMS` program; httpie's `-a`
 *  (`credential`, as its `--auth`); curl's
 *  `-b` (`--cookie`); `-b` after `gh secret` (`--body`). `program`: the
 *  letter belongs to the program, and when that program is the command
 *  itself (`isCommand`) it is read before a single-dash long flag's name
 *  (`mysql -pass` is the password `ass`). */
function letterSecretFlag(c: string, ctx: CommandContext): (SecretFlag & { program: boolean }) | null {
  const p = ctx.program;
  if (c === "u") return uidUser(ctx) ? null : { kind: "user", separate: true, program: false };
  if (c === "U") return p === "curl" ? { kind: "user", separate: true, program: false } : null;
  if (c === "H") return { kind: "header", separate: true, program: false };
  const own = p !== null && Object.hasOwn(PASSWORD_LETTER_FLAGS, p) ? PASSWORD_LETTER_FLAGS[p]! : null;
  if (own !== null && own.letter === c) return { kind: "whole", separate: own.separate, program: true };
  if (c === "p" && ctx.login && p !== null && LOGIN_PASSWORD_PROGRAMS.has(p)) return { kind: "whole", separate: true, program: true };
  if (c === "a" && p !== null && HTTPIE_PROGRAMS.has(p)) return { kind: "credential", separate: true, program: true };
  if (c === "b" && (p === "curl" || ctx.ghSecret)) return { kind: "whole", separate: true, program: true };
  return null;
}

/** A word that names a secret setting by its last word (`secretFlagName`,
 *  `/`, `:` and `@` read as word breaks): `config set <key> <value>`'s key
 *  (`//registry.npmjs.org/:_authToken`, `users.ci.token`). */
function secretSettingName(word: string): boolean {
  return secretFlagName(word.replace(/[:/@]+/g, "-"), true);
}

/**
 * The secret spans of one list's string items. An item is masked where:
 *   - the list sits under a secret-looking key: the whole item, as that
 *     key's string value would be (`valueSpan`: a URL keeps all but its
 *     password);
 *   - (a) it holds a URL with a password: the password (`args.3.password`);
 *   - (b) the content detector finds a credential format in it
 *     (`locateSecretShapes`: a provider's key, a private key block);
 *   - (c)-(e) the list is read as one command line, each item one word,
 *     and every item that holds a command line (`sh -c "…"`, a conninfo
 *     string, a quoted value) is read word by word too (`commandWords`, up
 *     to `MAX_COMMAND_DEPTH`): see `scanCommand` below.
 * A value that is wholly a reference resolved before the program runs is
 * left as written (`referenceValue`: `${API_KEY}`, `${input:token}`, and
 * `$API_KEY` where a shell expands it). Field `<list>.<index>`. Pure.
 *
 * 2026-10-10 (third review): the words of a command line inside an item
 * used to be matched by one regex that took the word after ANY flag as
 * that flag's value and went on after it, so a valueless switch before a
 * secret flag swallowed it (`curl -s -u admin:pw`, `--verbose --auth S`
 * stayed raw), and a header inside one item was never read. Now every word
 * is read, a non-secret flag takes nothing, and a word that starts with
 * `-` is a flag, never a value, unless it looks like a random credential
 * (`credentialShaped`: then it is the value and is still read as a flag).
 *
 * Fourth review (2026-10-10): any word whose basename was psql, mysql,
 * docker or podman set the program, so a path (`--datadir
 * /var/lib/mysql`), an image (`docker run mcp/mysql`) or a flag's value
 * (`--db-type mysql`) made a later `--password S` a prompt and `-u
 * admin:S` a user and group, and S stayed raw. The rules that mask less
 * now need the program to be the command word (`CommandContext.isCommand`,
 * `commandSlot`); and a `$`-led value is a reference only where something
 * resolves it (`referenceValue`), so `'$ecretPass99'` is masked.
 */
function listItemSpans(content: string, list: ListGroup): SecretSpan[] {
  const r: ListReader = { content, list, out: [] };
  scanCommand(r, list.items.map((item, i) => (item === null ? null : { text: item.text, item: i, idx: null, afterOperator: false })), listContext(list.command), 0);
  return r.out;
}

/** One list being read: the file's text, the list, the spans found. The
 *  readers below are module functions over it, not closures: the arbiter
 *  runs under tsx, whose kept names cost a `defineProperty` for every
 *  closure made, and a closure per word made a 256 KB item 0.4 s. */
interface ListReader { content: string; list: ListGroup; out: SecretSpan[] }

/** One command line being read (`scanCommand`): its words, the words a
 *  flag took as its value, what the words before say, and its depth. */
interface CommandScan { r: ListReader; words: ReadonlyArray<CommandWord | null>; taken: boolean[]; ctx: CommandContext; depth: number }

/** Field `<list>.<index>` of item i. */
function itemKey(r: ListReader, i: number): string {
  return `${r.list.name}.${i}`;
}

/** A span over [a, b) of item i's text, placed on the file's text. */
function placeOnItem(r: ListReader, i: number, key: string, a: number, b: number): void {
  if (b <= a) return;
  const item = r.list.items[i]!;
  const start = item.at[a]!;
  const end = item.at[b]!;
  if (end > start) r.out.push({ key, start, end, value: r.content.slice(start, end) });
}

/** A span over the characters [i, j) of word `w`. */
function placeWord(r: ListReader, w: CommandWord, key: string, i: number, j: number): void {
  if (j <= i) return;
  placeOnItem(r, w.item, key, w.idx === null ? i : w.idx[i]!, w.idx === null ? j : w.idx[j - 1]! + 1);
}

/** A value no credential is: one to three characters with no letter or
 *  digit (`$`, `*`, `-`). Masked, it would also be a needle that replaces
 *  the same punctuation everywhere in the twin. */
const PUNCTUATION_ONLY_RE = /^[^A-Za-z0-9]{1,3}$/;

/**
 * Is the value at [i, j) of `w` wholly a reference resolved before the
 * program runs (2026-10-10, fourth review)? In an item as the program gets
 * it (`idx` null: no shell reads it) only `${…}`, which the MCP client
 * expands (`bracedReference`); `$NAME` there reaches the program as it is,
 * so `["--password", "$ecretPass99"]` is a password. In a shell word,
 * `$NAME` and `${NAME}` too, unless the shell keeps that `$` as it is (in
 * single quotes or escaped: `--password '$ecretPass99'`).
 */
function referenceValue(w: CommandWord, i: number, j: number): boolean {
  const v = w.text.slice(i, j);
  if (w.idx === null) return bracedReference(v);
  return TEMPLATE_REFERENCE_RE.test(v) && !(w.literal?.has(i) ?? false);
}

/** The value at [i, j) of `w` may be a secret: not empty, no reference
 *  (`referenceValue`), not punctuation. */
function maskableAt(w: CommandWord, i: number, j: number): boolean {
  const v = w.text.slice(i, j);
  return v !== "" && !PUNCTUATION_ONLY_RE.test(v) && !referenceValue(w, i, j);
}

/** The value at [i, j) of `w` of a secret name, as `valueSpan` judges it
 *  (trailing blanks left out); nothing for a reference or punctuation. */
function secretWordValue(r: ListReader, w: CommandWord, i: number, j: number, key = itemKey(r, w.item)): void {
  while (j > i && /\s/.test(w.text[j - 1]!)) j--;
  if (!maskableAt(w, i, j)) return;
  const v = w.text.slice(i, j);
  const s = valueSpan(key, v, 0, true);
  if (s) placeWord(r, w, s.key, i + s.start, i + s.end);
}

/** (e) The `user:password` at [i, j) of `w`: the password, or the user
 *  when the password is empty; nothing for a bare user (the program
 *  asks), a URL, a reference or a numeric `uid:gid`. `credential`
 *  (httpie's `-a`): a value with no `:` is a token, masked whole, and a
 *  numeric `user:password` is one too. */
function userPasswordValue(r: ListReader, w: CommandWord, i: number, j: number, credential: boolean): void {
  const v = w.text.slice(i, j);
  const colon = v.indexOf(":");
  if (credential && (colon < 0 || v.includes("://"))) return secretWordValue(r, w, i, j);
  if (colon < 0 || v.includes("://") || (!credential && /^\d+:\d+$/.test(v))) return;
  const [u0, u1, p0, p1] = [i, i + colon, i + colon + 1, j];
  if (p1 > p0) {
    if (maskableAt(w, p0, p1)) placeWord(r, w, `${itemKey(r, w.item)}.password`, p0, p1);
  } else if (u1 > u0 && maskableAt(w, u0, u1)) {
    placeWord(r, w, itemKey(r, w.item), u0, u1);
  }
}

/** Rules (a), (b) and a secret-looking key's list, on item i. */
function itemRules(r: ListReader, i: number): void {
  const t = r.list.items[i]!.text;
  if (r.list.secretKey) secretWordValue(r, { text: t, item: i, idx: null, afterOperator: false }, 0, t.length);
  for (const [a, b] of urlPasswordsIn(t)) {
    // Only `${…}`: the item's text is read as it is here, quotes and all.
    if (!bracedReference(t.slice(a, b))) placeOnItem(r, i, `${itemKey(r, i)}.password`, a, b);
  }
  for (const s of locateSecretShapes(t)) placeOnItem(r, i, itemKey(r, i), s.start, s.end);
}

/**
 * One command line's words, in order, each read once:
 *   - (c) a flag that takes a secret (`longSecretFlag`, `letterSecretFlag`;
 *     a single-dash name such as Go's `-password`; the first such letter of
 *     a cluster such as `-fsSL`): its value after `=`, glued (`-uuser:pw`,
 *     `-pPW`, `-p=PW`) or, unless the program takes it glued only, the next
 *     word when that word is no flag (it starts with `-`, unless
 *     credential-shaped) and no shell operator stands between. Any other
 *     flag takes nothing, so a switch before a secret flag hides nothing:
 *     `curl -s -u admin:pw`;
 *   - (d) `NAME=VALUE` (`NAME:=`, `NAME==`) with a secret-looking NAME
 *     (`isSecretKey`, `ENV_SECRET_NAME_RE`): the VALUE, or in a form body
 *     whose every `&` piece is a pair, each secret pair's VALUE; `Name:
 *     value` with a secret-named header (`Authorization` past its scheme
 *     word, `X-API-Key`, `PRIVATE-TOKEN`): the value, which may be the next
 *     word or two (`-H Authorization: Bearer X` unquoted); a header after a
 *     non-secret `NAME=` (git's `-c http.extraHeader=…`) or a non-secret
 *     `--flag=`; `config set <key> <value>` (or `config <key> <value>`)
 *     with a secret-named key: the value;
 *   - (e) `user:password` after `-u`, `--user`, `--proxy-user` (curl's
 *     `-U`): the password, not after docker or podman (`uid:gid`); after
 *     httpie's `-a` / `--auth` the same, or a token with no `:` whole;
 *   - a word that holds blanks or quotes and matched none of these is read
 *     as a command line of its own, a level deeper, in a new context.
 * The program named last decides the program's letters that mask more
 * (`CommandContext.program`); `--password` taking no next word, `-u` being
 * a user and group, and a program's letter read before a Go-style name
 * hold only when the command word named it (`isCommand`, `commandSlot`).
 * A shell operator ends the command's context, and the word after `;`,
 * `&&`, `|`, `$(` and the like starts a new command. At depth 0 the words
 * are the list's items, after its `command` (`listContext`), and each item
 * that holds blanks, quotes or a backslash is read again as a command line
 * (depth 1, the program as it stands, no command word in it); the item
 * after `-c` (`sh -c`, `bash -lc`) only so, as a script: a new command
 * whose first word is the command word.
 */
function scanCommand(r: ListReader, words: ReadonlyArray<CommandWord | null>, ctx: CommandContext, depth: number): void {
  const sc: CommandScan = { r, words, taken: [], ctx, depth };
  for (let k = 0; k < words.length; k++) {
    const w = words[k];
    if (w === undefined || w === null) continue;
    if (w.afterOperator) operatorContext(ctx, w);
    const command = commandSlot(ctx, w.text);
    if (depth === 0) itemRules(r, w.item);
    // The item after `-c` (`sh -c`, `bash -lc`) is a script: read only as a
    // command line, so `PGPASSWORD=… psql -h db` masks the password, not the
    // whole rest as one value would be. Not a flag (`tool -c --token S`:
    // that `-c` is a switch).
    const script = depth === 0 && afterDashC(words, k);
    if (!script && w.text.startsWith("-")) flagWord(sc, k);
    else if (!script && !sc.taken[k]) plainWord(sc, k, command);
    // An item read as a command line: a script is a new command (its own
    // context, its first word the command word); any other item is words
    // of the list's own program, none of them the command word.
    if (depth === 0 && (script || (!sc.taken[k] && /[\s"'\\]/.test(w.text)))) {
      scanCommand(r, commandWords(w.text, w.item, null), script ? newContext("start") : { ...ctx, prev: null, slot: "args", wrapper: null }, 1);
    }
  }
}

/** Is words[k] a script: after `-c` (`sh -c`, `bash -lc`), and no flag? */
function afterDashC(words: ReadonlyArray<CommandWord | null>, k: number): boolean {
  const before = k > 0 ? words[k - 1] : null;
  return before !== null && before !== undefined && /^-[A-Za-z]*c$/.test(before.text) && !words[k]!.text.startsWith("-");
}

/** The word after words[k] if a flag may take it as its value. */
function valueAfter(sc: CommandScan, k: number): number {
  const v = sc.words[k + 1];
  if (v === undefined || v === null || v.afterOperator) return -1;
  if (v.text.startsWith("-") && !credentialShaped(v.text)) return -1;
  return k + 1;
}

/** A header at [i, j) of `w` (words[k]): the value of a secret-named one,
 *  or the next word or two when it has none here. True if it is one. */
function headerValue(sc: CommandScan, w: CommandWord, i: number, j: number, k: number): boolean {
  HEADER_AT_RE.lastIndex = i;
  const m = HEADER_AT_RE.exec(w.text);
  if (m === null || HEADER_AT_RE.lastIndex > j) return false;
  const name = m[1]!.toLowerCase();
  const auth = name === "authorization" || name === "proxy-authorization";
  if (!auth && !secretFlagName(name, true)) return false;
  let at = HEADER_AT_RE.lastIndex;
  let scheme = false;
  if (auth) {
    const rest = w.text.slice(at, j);
    const sm = AUTH_SCHEME_RE.exec(rest);
    if (sm !== null) [at, scheme] = [at + sm[0].length, true];
    else if (AUTH_SCHEME_WORD_RE.test(rest.trim())) [at, scheme] = [j, true];
  }
  if (w.text.slice(at, j).trim() !== "") {
    secretWordValue(sc.r, w, at, j);
    return true;
  }
  // The value is in the next words (`-H Authorization: Bearer X` unquoted).
  if (j !== w.text.length) return true;
  let v = valueAfter(sc, k);
  if (v >= 0 && auth && !scheme && AUTH_SCHEME_WORD_RE.test(sc.words[v]!.text)) {
    sc.taken[v] = true;
    v = valueAfter(sc, v);
  }
  if (v >= 0) {
    sc.taken[v] = true;
    secretWordValue(sc.r, sc.words[v]!, 0, sc.words[v]!.text.length);
  }
  return true;
}

/** The value at [i, j) of `w` (words[k]) of a flag of `kind`. */
function judgeFlagValue(sc: CommandScan, kind: FlagKind, w: CommandWord, i: number, j: number, k: number): void {
  if (kind === "whole") secretWordValue(sc.r, w, i, j);
  else if (kind === "user" || kind === "credential") userPasswordValue(sc.r, w, i, j, kind === "credential");
  else headerValue(sc, w, i, j, k);
}

/** The flag at words[k] takes the next word as its value, if it is one. */
function takeNextWord(sc: CommandScan, kind: FlagKind, k: number): void {
  const v = valueAfter(sc, k);
  if (v < 0) return;
  sc.taken[v] = true;
  judgeFlagValue(sc, kind, sc.words[v]!, 0, sc.words[v]!.text.length, v);
}

/** Field of a `NAME=` value: the item's at depth 0, `<item>.<NAME>` inside. */
function assignmentKey(sc: CommandScan, w: CommandWord, name: string): string {
  return sc.depth === 0 ? itemKey(sc.r, w.item) : `${itemKey(sc.r, w.item)}.${fieldSegment(name, "value")}`;
}

/** (d) on `w` (words[k]) from i: a header, a form body, else `NAME=`. True
 *  if it masked or took a value. */
function valueRules(sc: CommandScan, w: CommandWord, i: number, k: number): boolean {
  if (headerValue(sc, w, i, w.text.length, k)) return true;
  if (w.text.includes("&", i) && formPairs(sc, w, i)) return true;
  ASSIGNMENT_AT_RE.lastIndex = i;
  const a = ASSIGNMENT_AT_RE.exec(w.text);
  if (a === null) return false;
  const name = a[1]!;
  const at = ASSIGNMENT_AT_RE.lastIndex;
  if (isSecretKey(name) || ENV_SECRET_NAME_RE.test(name)) {
    secretWordValue(sc.r, w, at, w.text.length, assignmentKey(sc, w, name));
    return true;
  }
  return headerValue(sc, w, at, w.text.length, k);
}

/** A form body from i (`a=1&client_secret=…`, every `&` piece a
 *  `NAME=VALUE`): each secret-named pair's VALUE. False when a piece is no
 *  pair (`PASSWORD=p&ss` is one value; a URL's query is no form body) or
 *  none is secret. */
function formPairs(sc: CommandScan, w: CommandWord, i: number): boolean {
  const pairs: Array<[string, number, number]> = [];
  for (let a = i; a <= w.text.length;) {
    let b = w.text.indexOf("&", a);
    if (b < 0) b = w.text.length;
    ASSIGNMENT_AT_RE.lastIndex = a;
    const m = ASSIGNMENT_AT_RE.exec(w.text);
    if (m === null || ASSIGNMENT_AT_RE.lastIndex > b) return false;
    pairs.push([m[1]!, ASSIGNMENT_AT_RE.lastIndex, b]);
    a = b + 1;
  }
  let masked = false;
  for (const [name, a, b] of pairs) {
    if (!isSecretKey(name) && !ENV_SECRET_NAME_RE.test(name)) continue;
    secretWordValue(sc.r, w, a, b, assignmentKey(sc, w, name));
    masked = true;
  }
  return masked;
}

/** words[k], which starts with `-`: (c) and (e). */
function flagWord(sc: CommandScan, k: number): void {
  const w = sc.words[k]!;
  const s = w.text;
  if (s.startsWith("--")) {
    const eq = s.indexOf("=");
    const f = longSecretFlag(s.slice(2, eq < 0 ? s.length : eq), sc.ctx);
    if (f !== null && eq >= 0) judgeFlagValue(sc, f.kind, w, eq + 1, s.length, k);
    else if (f !== null) { if (f.separate) takeNextWord(sc, f.kind, k); }
    else if (eq >= 0) valueRules(sc, w, eq + 1, k);
    return;
  }
  if (!/^-[A-Za-z]/.test(s)) return; // `-`, `-1`: no flag
  const first = letterSecretFlag(s[1]!, sc.ctx);
  // A program's letter goes first only when that program is the command:
  // `--db-type mysql -password S` is Go's `-password`, not `-p` `assword`.
  if (first === null || !first.program || !sc.ctx.isCommand) {
    // A single-dash long name (Go's `-password`, `-api-key=…`, `-user a:pw`).
    const eq = s.indexOf("=");
    const name = s.slice(1, eq < 0 ? s.length : eq);
    const user = name.toLowerCase() === "user";
    const kind: FlagKind | null = name.length < 2 || (user && uidUser(sc.ctx)) ? null : user ? "user" : secretFlagName(name, false) ? "whole" : null;
    if (kind !== null) {
      if (eq >= 0) judgeFlagValue(sc, kind, w, eq + 1, s.length, k);
      else takeNextWord(sc, kind, k);
      return;
    }
  }
  // A cluster of one-letter flags: the first that takes a secret.
  for (let j = 1; j < s.length && /[A-Za-z]/.test(s[j]!); j++) {
    const f = letterSecretFlag(s[j]!, sc.ctx);
    if (f === null) continue;
    const g = s[j + 1] === "=" ? j + 2 : j + 1;
    if (g < s.length) judgeFlagValue(sc, f.kind, w, g, s.length, k);
    else if (f.separate) takeNextWord(sc, f.kind, k);
    return;
  }
}

/** words[k], no flag and not taken: the context it sets (`command`: it is
 *  the command word), (d), and a command line inside it. */
function plainWord(sc: CommandScan, k: number, command: boolean): void {
  const w = sc.words[k]!;
  const s = w.text;
  const ctx = sc.ctx;
  const prev = ctx.prev;
  if (!/\s/.test(s)) wordContext(ctx, s, command);
  else if (command) [ctx.program, ctx.isCommand] = [null, false];
  if (valueRules(sc, w, 0, k)) return;
  if ((prev === "set" || prev === "config") && !s.includes("=") && secretSettingName(s)) {
    takeNextWord(sc, "whole", k);
    return;
  }
  if (sc.depth > 0 && sc.depth < MAX_COMMAND_DEPTH && /[\s"'\\]/.test(s)) {
    // A script (`bash -c '…'`) starts with its command word; any other
    // quoted text read as words (`psql "host=… password=…"`, `ssh host
    // "…"`) has none Mandu can be sure of.
    scanCommand(sc.r, commandWords(s, w.item, w.idx), newContext(afterDashC(sc.words, k) ? "start" : "args"), sc.depth + 1);
  }
}

/** The text of a quoted string whose opening quote is at `open`, decoded,
 *  with each character's file offset (`ListItem`), and the offset just
 *  past its closing quote. `style`: `backslash` (JSON, a YAML or TOML
 *  double-quoted string: `\n`, `\"`, `\xHH`, `\uHHHH`, `\UHHHHHHHH`),
 *  `literal` (a TOML single-quoted string: no escapes) or `doubled` (a YAML
 *  single-quoted string: `''` is one quote). A string that does not close
 *  on its own line ends there (`end` is that line's end). Pure. */
function quotedAt(content: string, open: number, style: "backslash" | "literal" | "doubled"): ListItem & { end: number } {
  const q = content[open]!;
  const at: number[] = [];
  let text = "";
  let j = open + 1;
  while (j < content.length) {
    const c = content[j]!;
    if (c === "\n" || c === "\r") break;
    if (c === q) {
      if (style === "doubled" && content[j + 1] === q) { at.push(j); text += q; j += 2; continue; }
      at.push(j);
      return { text, at, end: j + 1 };
    }
    if (c === "\\" && style === "backslash" && j + 1 < content.length) {
      const e = content[j + 1]!;
      const hex = e === "x" ? 2 : e === "u" ? 4 : e === "U" ? 8 : 0;
      const digits = hex > 0 ? content.slice(j + 2, j + 2 + hex) : "";
      let ch: string;
      let len = 2;
      if (hex > 0 && digits.length === hex && /^[0-9A-Fa-f]+$/.test(digits)) {
        const cp = parseInt(digits, 16);
        ch = cp <= 0x10ffff ? String.fromCodePoint(cp) : "\ufffd";
        len = 2 + hex;
      } else {
        ch = ({ n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", "0": "\0" } as Record<string, string>)[e] ?? e;
      }
      for (let k = 0; k < ch.length; k++) at.push(j);
      text += ch;
      j += len;
      continue;
    }
    at.push(j);
    text += c;
    j++;
  }
  at.push(j);
  return { text, at, end: j };
}

/** An unquoted item `[start, end)` of the file, trailing blanks dropped. */
function plainAt(content: string, start: number, end: number): ListItem {
  let e = end;
  while (e > start && /\s/.test(content[e - 1]!)) e--;
  const at: number[] = [];
  for (let k = start; k <= e; k++) at.push(k);
  return { text: content.slice(start, e), at };
}

/** The offset just past the JSON string whose `"` is at `open` (its line's
 *  end when it never closes). Pure. */
function jsonStringEnd(content: string, open: number): number {
  for (let j = open + 1; j < content.length; j++) {
    const c = content[j];
    if (c === "\\") { j++; continue; }
    if (c === '"') return j + 1;
    if (c === "\n" || c === "\r") return j;
  }
  return content.length;
}

/** The text of the JSON string at [open, end): decoded when it is valid
 *  JSON, else its raw inside. Pure. */
function jsonStringText(content: string, open: number, end: number): string {
  const raw = content.slice(open, end);
  if (!raw.includes("\\")) return raw.slice(1, raw.endsWith('"') && raw.length > 1 ? -1 : undefined);
  try {
    return JSON.parse(raw) as string;
  } catch {
    return raw.slice(1);
  }
}

/**
 * Every array of a JSON text (JSONC too: `//` and `/* *\/` comments are
 * skipped), with its string items and the `command` string of the object
 * it is a member of. A list's name is its key (`args`; a nested list
 * `<outer>.<index>`, a top-level one `list`). Tolerant: broken structure
 * never throws, an unbalanced closer is ignored, an unclosed string ends at
 * its line. Null when objects and arrays nest deeper than `MAX_LIST_DEPTH`
 * (the caller hides the file whole). Linear: a closer with no open
 * container of its kind is ignored without a walk down the stack (one walk
 * per closer made `{` × 50 000 then `]` × 50 000 take 5 s). Pure.
 */
function jsonLists(content: string): ListGroup[] | null {
  type Obj = { kind: "obj"; key: string | null; colon: boolean; command?: string };
  type Arr = { kind: "arr"; group: ListGroup; owner: Obj | null };
  const stack: Array<Obj | Arr> = [];
  const open = { obj: 0, arr: 0 }; // how many of each kind `stack` holds
  const groups: Array<{ group: ListGroup; owner: Obj | null }> = [];
  const bare = /[^\s,:[\]{}"/]+/y;
  let i = 0;
  while (i < content.length) {
    const c = content[i]!;
    const top = stack[stack.length - 1];
    if (c === '"') {
      if (top?.kind === "arr") {
        const s = quotedAt(content, i, "backslash");
        top.group.items.push({ text: s.text, at: s.at });
        i = Math.max(s.end, i + 1);
        continue;
      }
      // A key or a member's value: only its text, and only when needed (a
      // large `.tfstate` is mostly these).
      const end = jsonStringEnd(content, i);
      if (top?.kind === "obj") {
        if (!top.colon) top.key = jsonStringText(content, i, end);
        else {
          if (top.key === "command") top.command = jsonStringText(content, i, end);
          top.colon = false;
        }
      }
      i = Math.max(end, i + 1);
    } else if (c === "/" && content[i + 1] === "/") {
      const nl = content.indexOf("\n", i);
      i = nl < 0 ? content.length : nl;
    } else if (c === "/" && content[i + 1] === "*") {
      const close = content.indexOf("*/", i + 2);
      i = close < 0 ? content.length : close + 2;
    } else if (c === "{") {
      if (stack.length >= MAX_LIST_DEPTH) return null;
      if (top?.kind === "arr") top.group.items.push(null);
      stack.push({ kind: "obj", key: null, colon: false });
      open.obj++;
      i++;
    } else if (c === "[") {
      if (stack.length >= MAX_LIST_DEPTH) return null;
      let group: ListGroup;
      if (top?.kind === "obj") group = { name: fieldSegment(top.key ?? "", "list"), secretKey: isSecretKey(top.key ?? ""), items: [] };
      else if (top?.kind === "arr") {
        group = { name: `${top.group.name}.${top.group.items.length}`, secretKey: top.group.secretKey, items: [] };
        top.group.items.push(null);
      } else group = { name: "list", secretKey: false, items: [] };
      if (group.name.length > MAX_LIST_NAME) return null;
      const owner = top?.kind === "obj" ? top : null;
      groups.push({ group, owner });
      stack.push({ kind: "arr", group, owner });
      open.arr++;
      i++;
    } else if (c === "}" || c === "]") {
      const want = c === "}" ? "obj" : "arr";
      if (open[want] > 0) {
        // Pop to the nearest container of that kind (each entry is popped once).
        for (let e = stack.pop(); e !== undefined; e = stack.pop()) {
          open[e.kind]--;
          if (e.kind === want) break;
        }
      }
      const parent = stack[stack.length - 1];
      if (parent?.kind === "obj") parent.colon = false;
      i++;
    } else if (c === ":") {
      if (top?.kind === "obj") top.colon = true;
      i++;
    } else if (c === ",") {
      if (top?.kind === "obj") { top.colon = false; top.key = null; }
      i++;
    } else if (/\s/.test(c)) {
      i++;
    } else {
      // A bare token (a number, true, false, null) or a stray character.
      bare.lastIndex = i;
      const m = bare.exec(content);
      if (top?.kind === "arr") top.group.items.push(null);
      else if (top?.kind === "obj" && top.colon) top.colon = false;
      i += m ? m[0].length : 1;
    }
  }
  return groups.map(({ group, owner }) => (owner?.command !== undefined ? { ...group, command: owner.command } : group));
}

/** The items of a flow list (`[a, "b", c]`) whose `[` is at `open`, in a
 *  YAML (`yaml`) or TOML text, across lines; nested lists become groups of
 *  their own (`<name>.<index>`). Returns the offset past its `]`, or -1
 *  when it never closes or nests deeper than `MAX_LIST_DEPTH` (2026-10-10:
 *  the caller hides the file whole; an unclosed list used to swallow the
 *  rest of the file, so no later list was read). A `#` comment runs to its
 *  line's end (YAML: only after a blank). Pure. */
function flowList(content: string, open: number, group: ListGroup, groups: ListGroup[], style: "yaml" | "toml", depth = 1): number {
  if (depth > MAX_LIST_DEPTH || group.name.length > MAX_LIST_NAME) return -1;
  groups.push(group);
  let i = open + 1;
  while (i < content.length) {
    const c = content[i]!;
    if (c === "]") return i + 1;
    if (c === "," || /\s/.test(c)) { i++; continue; }
    if (c === "#") {
      const nl = content.indexOf("\n", i);
      i = nl < 0 ? content.length : nl;
      continue;
    }
    if (c === "[") {
      const nested: ListGroup = { name: `${group.name}.${group.items.length}`, secretKey: group.secretKey, items: [] };
      group.items.push(null);
      i = flowList(content, i, nested, groups, style, depth + 1);
      if (i < 0) return -1;
      continue;
    }
    if (c === "{") {
      // An inline table or flow mapping: skip it (its keys are not list items).
      let depth = 0;
      for (; i < content.length; i++) {
        const d = content[i];
        if (d === "{") depth++;
        else if (d === "}" && --depth === 0) { i++; break; }
        else if (d === '"' || d === "'") i = quotedAt(content, i, d === "'" ? (style === "toml" ? "literal" : "doubled") : "backslash").end - 1;
      }
      group.items.push(null);
      continue;
    }
    if (c === '"' || c === "'") {
      const s = quotedAt(content, i, c === "'" ? (style === "toml" ? "literal" : "doubled") : "backslash");
      group.items.push({ text: s.text, at: s.at });
      i = Math.max(s.end, i + 1);
      continue;
    }
    // A plain item: to the next `,` `]` or line end (YAML: or ` #`).
    let e = i;
    while (e < content.length && !/[,\]\n\r]/.test(content[e]!) && !(content[e] === "#" && (style === "toml" || /\s/.test(content[e - 1] ?? "")))) e++;
    // A TOML number, boolean or date is no string; a YAML plain scalar is.
    group.items.push(style === "toml" ? null : { ...plainAt(content, i, e), flowPlain: true });
    i = Math.max(e, i + 1);
  }
  return -1;
}

/**
 * YAML (2026-10-10): a plain item of a flow sequence cannot hold a
 * placeholder as written. `[` and `]` inside it are flow indicators, so
 * `args: [-y, --token=$MDU:nomodel_Read[e34d].args.1]` no longer parses.
 * Each such item that holds a span becomes one span over the whole item,
 * which the twin writes single-quoted (`wrap`, as dotenv does):
 * `'--token=$MDU:nomodel_Read[e34d].args.1'`. Two spans in one item become
 * one placeholder (the text between them is hidden too, the fail-safe
 * direction); an item whose text around the secret single quotes cannot
 * hold as written (a quote, a backslash) is one placeholder whole. Either
 * way each secret in it stays a part of that span (`SecretSpan.parts`), so
 * a copy of it elsewhere in the file is still masked and the registry
 * still holds its value. A span that crosses the item's edge (a keyed span
 * read across a flow line) is left as it is. `spans` sorted and disjoint,
 * as `finishMerged` returns them. Pure.
 */
function quotedPlainFlowItems(content: string, spans: readonly SecretSpan[], lists: readonly ListGroup[]): SecretSpan[] {
  const items: Array<{ start: number; end: number }> = [];
  for (const g of lists) {
    for (const it of g.items) if (it?.flowPlain) items.push({ start: it.at[0]!, end: it.at[it.text.length]! });
  }
  if (items.length === 0) return [...spans];
  items.sort((a, b) => a.start - b.start);
  const out: SecretSpan[] = [];
  let k = 0;
  let j = 0;
  while (j < spans.length) {
    const s = spans[j]!;
    while (k < items.length && items[k]!.end <= s.start) k++;
    const it = items[k];
    if (it === undefined || s.end <= it.start) { out.push(s); j++; continue; }
    // Every span that meets this item.
    let e = j;
    while (e + 1 < spans.length && spans[e + 1]!.start < it.end) e++;
    const meets = spans.slice(j, e + 1);
    j = e + 1;
    const before = out[out.length - 1];
    if ((before !== undefined && before.end > it.start) || meets.some((m) => m.start < it.start || m.end > it.end)) {
      out.push(...meets);
      continue;
    }
    const first = meets[0]!;
    const last = meets[meets.length - 1]!;
    const prefix = content.slice(it.start, first.start);
    const suffix = content.slice(last.end, it.end);
    const whole = /['\\\r\n]/.test(prefix + suffix);
    if (!whole && meets.length === 1) {
      out.push({ key: first.key, start: it.start, end: it.end, value: first.value, wrap: { prefix, suffix }, ...(first.parts ? { parts: first.parts } : {}) });
      continue;
    }
    // One placeholder over several secrets, or over the whole item: its
    // value is that text, and each secret in it stays a part (2026-10-10:
    // until then a copy of one of them elsewhere in the file stayed raw).
    out.push({
      key: first.key,
      start: it.start,
      end: it.end,
      value: whole ? content.slice(it.start, it.end) : content.slice(first.start, last.end),
      wrap: whole ? { prefix: "", suffix: "" } : { prefix, suffix },
      parts: meets.flatMap(secretsOf),
    });
  }
  return out;
}

/** A YAML plain or quoted scalar at `start` (the rest of its line):
 *  quotes removed and escapes decoded, a plain one cut before ` #`. Null
 *  for a block scalar (`|`, `>`), an alias, a flow mapping or nothing. */
function yamlScalarAt(content: string, start: number, lineEnd: number): ListItem | null {
  const c = content[start];
  if (start >= lineEnd || c === "|" || c === ">" || c === "*" || c === "{" || c === "#") return null;
  if (c === '"' || c === "'") {
    const s = quotedAt(content, start, c === "'" ? "doubled" : "backslash");
    return { text: s.text, at: s.at };
  }
  let e = start;
  while (e < lineEnd && !(content[e] === "#" && /\s/.test(content[e - 1] ?? ""))) e++;
  return plainAt(content, start, e);
}

/** A YAML mapping key at the start of `body` (`key: …`, `"a b": …`), as
 *  YAML reads it: the `:` must be followed by a blank or the line's end,
 *  so `postgres://u:p@h` and `--token=a:b` are no keys. Group 1 a quoted
 *  key, group 2 a plain one (trailing blanks kept). Linear (2026-10-10):
 *  a plain key's lazy run is followed by the `:` alone; a blank run before
 *  the `:` there made a 16 KB line of blanks take 0.4 s. */
const YAML_KEY_RE = /^(?:("(?:[^"\\]|\\.)*"|'(?:[^']|'')*')[ \t]*|([^\s#'"[\]{},&*!|>%@`-][^#]*?|-[^\s#][^#]*?)):(?=[ \t]|$)[ \t]*/;

/** A YAML block scalar's header (`|`, `>-`, `|2`, a comment after it): the
 *  lines indented deeper than its key or item are its text, no YAML. */
const YAML_BLOCK_SCALAR_RE = /^[|>][-+0-9]*[ \t]*(?:#.*)?$/;

/**
 * Every sequence of a YAML text: block sequences (`- item` lines) and flow
 * sequences (`key: [a, b]`, over several lines too), with their string
 * items, named by the path of keys above them (`servers.brave.args`; a
 * top-level one `list`), and the `command` scalar of the mapping they sit
 * in (a new mapping starts at each `- ` item). Line-based like
 * `extractYamlKeys`: a block scalar item (`- |`) is no string item, a plain
 * or quoted item that continues on the next line is read as its first
 * line, and a sequence nested in a sequence item (`- - a`) names only the
 * items on that line by their place. The text of a block scalar (`script:
 * |` and the lines under it) is skipped (2026-10-10: a `key: [` line in it
 * opened a flow list that swallowed the rest of the file). Null when a
 * flow sequence never closes or lists nest deeper than `MAX_LIST_DEPTH`
 * (the caller hides the file whole). Pure.
 */
function yamlLists(content: string): ListGroup[] | null {
  type Scope = { col: number; command?: string };
  type Entry = { indent: number; name: string; secret: boolean; scope: Scope; seq?: { col: number; group: ListGroup } };
  const groups: ListGroup[] = [];
  const scopeOf = new Map<ListGroup, Scope>();
  let root: Entry = { indent: -1, name: "list", secret: false, scope: { col: -1 } };
  let stack: Entry[] = [];
  let scopes: Scope[] = [];
  const pathOf = (key?: string): string =>
    [...stack.map((e) => fieldSegment(e.name, "key")), ...(key === undefined ? [] : [fieldSegment(key, "key")])].join(".");
  const unquoteKey = (raw: string): string => (/^(["']).*\1$/.test(raw) ? raw.slice(1, -1) : raw.trimEnd());
  let tooLong = false; // a block sequence's name passed MAX_LIST_NAME
  const newGroup = (name: string, secretKey: boolean, scope: Scope): ListGroup => {
    const g: ListGroup = { name, secretKey, items: [] };
    if (name.length > MAX_LIST_NAME) tooLong = true;
    groups.push(g);
    scopeOf.set(g, scope);
    return g;
  };
  let skipTo = 0; // past a flow sequence that ran over several lines
  let blockAbove: number | null = null; // in a block scalar: its lines are indented deeper than this
  let at = 0;
  while (at <= content.length) {
    let lineEnd = content.indexOf("\n", at);
    if (lineEnd < 0) lineEnd = content.length;
    const next = lineEnd + 1;
    const line = content.slice(at, lineEnd > at && content[lineEnd - 1] === "\r" ? lineEnd - 1 : lineEnd);
    if (at < skipTo || /^\s*(?:#|$)/.test(line)) { at = next; continue; }
    let col = line.length - line.trimStart().length;
    if (blockAbove !== null) {
      if (col > blockAbove) { at = next; continue; }
      blockAbove = null;
    }
    if (/^(?:---|\.\.\.)(?:\s|$)/.test(line)) {
      root = { indent: -1, name: "list", secret: false, scope: { col: -1 } };
      stack = [];
      scopes = [];
      at = next;
      continue;
    }
    // Each `- ` marker opens an item of the sequence at its column; a
    // second marker on the line makes that item a sequence itself.
    let cur: ListGroup | null = null;
    let dashCol = -1;
    let dashes = 0;
    while (line[col] === "-" && (col + 1 === line.length || line[col + 1] === " " || line[col + 1] === "\t")) {
      if (++dashes > MAX_LIST_DEPTH) return null;
      dashCol = col;
      if (cur === null) {
        while (stack.length && stack[stack.length - 1]!.indent > col) stack.pop();
        while (scopes.length && scopes[scopes.length - 1]!.col > col) scopes.pop();
        const owner = stack[stack.length - 1] ?? root;
        if (owner.seq?.col !== col) owner.seq = { col, group: newGroup(owner === root ? "list" : pathOf(), owner.secret, owner.scope) };
        cur = owner.seq.group;
      } else {
        const nested = newGroup(`${cur.name}.${cur.items.length}`, cur.secretKey, scopeOf.get(cur)!);
        cur.items.push(null);
        cur = nested;
      }
      col++;
      while (line[col] === " " || line[col] === "\t") col++;
    }
    if (tooLong) return null;
    const body = line.slice(col);
    const k = YAML_KEY_RE.exec(body);
    if (cur !== null && k === null) {
      // A scalar, a flow sequence, or nothing (a block follows) as the item.
      if (body.startsWith("[")) {
        const nested: ListGroup = { name: `${cur.name}.${cur.items.length}`, secretKey: cur.secretKey, items: [] };
        scopeOf.set(nested, scopeOf.get(cur)!);
        cur.items.push(null);
        skipTo = flowList(content, at + col, nested, groups, "yaml");
        if (skipTo < 0) return null;
      } else {
        // A block scalar item (`- |`) is no string item; its text is skipped.
        if (YAML_BLOCK_SCALAR_RE.test(body)) blockAbove = dashCol;
        cur.items.push(yamlScalarAt(content, at + col, at + line.length));
      }
      at = next;
      continue;
    }
    if (k === null) { at = next; continue; }
    // A mapping key at `col`; on an item line it opens the item's mapping.
    if (cur !== null) cur.items.push(null);
    while (stack.length && stack[stack.length - 1]!.indent >= col) stack.pop();
    while (scopes.length && scopes[scopes.length - 1]!.col > col) scopes.pop();
    if (cur !== null) while (scopes.length && scopes[scopes.length - 1]!.col >= col) scopes.pop();
    let scope = scopes[scopes.length - 1];
    if (scope === undefined || scope.col !== col) {
      scope = { col };
      scopes.push(scope);
    }
    const key = unquoteKey(k[1] ?? k[2]!);
    const valueAt = at + col + k[0].length;
    const value = content.slice(valueAt, at + line.length);
    if (value === "" || value.startsWith("#")) {
      stack.push({ indent: col, name: key, secret: isSecretKey(key), scope });
    } else if (YAML_BLOCK_SCALAR_RE.test(value)) {
      blockAbove = col;
    } else if (value.startsWith("[")) {
      const group: ListGroup = { name: pathOf(key), secretKey: isSecretKey(key), items: [] };
      scopeOf.set(group, scope);
      skipTo = flowList(content, valueAt, group, groups, "yaml");
      if (skipTo < 0) return null;
    } else if (key === "command") {
      const s = yamlScalarAt(content, valueAt, at + line.length);
      if (s !== null) scope.command = s.text;
    }
    at = next;
  }
  return withCommands(groups, scopeOf);
}

/** `groups` with the `command` their scope holds (read once the whole
 *  file is: a `command` key may follow the list it applies to). */
function withCommands(groups: readonly ListGroup[], scopeOf: ReadonlyMap<ListGroup, { command?: string }>): ListGroup[] {
  return groups.map((g) => {
    const command = scopeOf.get(g)?.command;
    return command !== undefined ? { ...g, command } : g;
  });
}

/** A TOML key: bare, quoted or dotted (`args`, `"a b"`, `a.b`). */
const TOML_KEY_RE = /^\s*((?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|'[^']*')(?:\s*\.\s*(?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|'[^']*'))*)\s*=\s*/;

/** A TOML table header (`[mcp_servers.brave]`, `[[servers]]`). */
const TOML_TABLE_RE = /^\s*\[\[?\s*((?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|'[^']*')(?:\s*\.\s*(?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|'[^']*'))*)\s*\]\]?\s*(?:#.*)?$/;

/** A dotted TOML key's parts, unquoted. */
function tomlKeyParts(raw: string): string[] {
  return (raw.match(/"(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+/g) ?? []).map((p) => (/^["']/.test(p) ? p.slice(1, -1) : p));
}

/**
 * Every array of a TOML text (`args = ["-y", "pkg"]`, over several lines
 * too, nested arrays included), with its string items, named
 * `<table>.<key>` (`mcp_servers.brave.args`), and the `command` string of
 * its table (a new table starts at each header). Its numbers, booleans
 * and dates are no string items. Null when an array never closes or nests
 * deeper than `MAX_LIST_DEPTH` (the caller hides the file whole). Pure.
 */
function tomlLists(content: string): ListGroup[] | null {
  const groups: ListGroup[] = [];
  const scopeOf = new Map<ListGroup, { command?: string }>();
  let table: string[] = [];
  let scope: { command?: string } = {};
  let skipTo = 0;
  let at = 0;
  while (at <= content.length) {
    let lineEnd = content.indexOf("\n", at);
    if (lineEnd < 0) lineEnd = content.length;
    const next = lineEnd + 1;
    if (at < skipTo) { at = next; continue; }
    const line = content.slice(at, lineEnd > at && content[lineEnd - 1] === "\r" ? lineEnd - 1 : lineEnd);
    const header = TOML_TABLE_RE.exec(line);
    if (header !== null) {
      table = tomlKeyParts(header[1]!);
      scope = {};
      at = next;
      continue;
    }
    const m = TOML_KEY_RE.exec(line);
    if (m !== null) {
      const parts = tomlKeyParts(m[1]!);
      const key = parts[parts.length - 1] ?? "";
      const valueAt = at + m[0].length;
      const c = content[valueAt];
      if (c === "[") {
        const group: ListGroup = { name: [...table, ...parts].map((p) => fieldSegment(p, "key")).join("."), secretKey: isSecretKey(key), items: [] };
        scopeOf.set(group, scope);
        skipTo = flowList(content, valueAt, group, groups, "toml");
        if (skipTo < 0) return null;
      } else if (parts.length === 1 && key === "command" && (c === '"' || c === "'")) {
        scope.command = quotedAt(content, valueAt, c === "'" ? "literal" : "backslash").text;
      }
    }
    at = next;
  }
  return withCommands(groups, scopeOf);
}

/** The user's own regex: group 1 of every match. */
function extractByRegex(content: string, pattern: string): SecretExtraction {
  let re: RegExp;
  try {
    re = new RegExp(pattern, pattern.includes("\n") ? "gm" : "gm");
  } catch {
    return NONE;
  }
  const spans: SecretSpan[] = [];
  let m: RegExpExecArray | null;
  let n = 0;
  while ((m = re.exec(content)) !== null) {
    if (m[0] === "") { re.lastIndex++; continue; }
    if (m[1] === undefined || m[1] === "") continue;
    const start = m.index + m[0].indexOf(m[1]);
    spans.push({ key: `extract_${++n}`, start, end: start + m[1].length, value: m[1] });
  }
  if (spans.length === 0) return NONE; // a pattern that matched nothing keeps the whole file masked
  return finish("extract", spans);
}

// ── exhaustive configuration shapes (2026-10-02) ────────────────────────────
//
// FAIL CLOSED (plan 10 §11.13.2, 2026-10-02). An own-text twin is the file's
// text with only the spans below replaced, so whatever the extractor does
// not mask reaches every program that reads the twin. Until then it masked
// only what it recognized as a secret (a URL password, a secret-looking
// name, `sshpass -p`), and a bare password in a `ProxyCommand`, a token in an
// index URL's path or a `SetEnv FOO=hunter2` sat raw. Now the rule is the
// reverse: a place stays raw only when the format says it is public (an ssh
// keyword whose value is a host, a port, a path, a flag; a pip option; a
// URL's scheme and host) and its content has the public shape; everything
// else (an unknown keyword or key, a command no grammar below vouches for,
// every `SetEnv` value, a comment, a URL path segment or query value shaped
// like a random credential, a user name that is not a plain word) is
// masked. On top, the content detector (`locateSecretShapes`, the scans'
// credential formats) masks any credential shape left anywhere in the text.

/** A reference to an environment variable, which is not itself a secret
 *  (`https://${PIP_TOKEN}@host`, `SetEnv TOKEN=$TOKEN`). */
const ENV_REFERENCE_RE = /^\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)$/;

/** A host or block name as a field-name segment. */
function fieldSegment(s: string, fallback: string): string {
  const t = s.replace(/[^A-Za-z0-9_.]/g, "_").replace(/^\.+|\.+$/g, "");
  return t === "" ? fallback : t.slice(0, 64);
}

/** Strip one pair of matching quotes from a matched value, moving its start. */
function stripQuotes(raw: string, start: number): { value: string; start: number } {
  if (raw.length >= 2 && (raw[0] === '"' || raw[0] === "'") && raw[raw.length - 1] === raw[0]) {
    return { value: raw.slice(1, -1), start: start + 1 };
  }
  return { value: raw, start };
}

/** A span over `value` starting at absolute offset `start`. */
const spanAt = (key: string, start: number, value: string): SecretSpan => ({ key, start, end: start + value.length, value });

/** One run of letters and digits shaped like a random credential: 12+
 *  characters mixing letters and digits, 16+ mixing upper and lower case,
 *  or 32+ of anything (a hex digest, a base32 PAT). Words, version numbers,
 *  numeric ids, host labels and the like are shorter or unmixed. */
function randomRun(p: string): boolean {
  return (p.length >= 12 && /[A-Za-z]/.test(p) && /[0-9]/.test(p))
    || (p.length >= 16 && /[a-z]/.test(p) && /[A-Z]/.test(p))
    || p.length >= 32;
}

/** Does a word of a public place (a URL path segment, a query value, a
 *  command argument, a key name) carry a run shaped like a credential? An
 *  environment variable reference does not. Pure. */
export function credentialShaped(s: string): boolean {
  if (ENV_REFERENCE_RE.test(s)) return false;
  return s.split(/[^A-Za-z0-9]+/).some(randomRun);
}

/** A word that may stay raw: an environment variable reference, or only
 *  `charset` characters and no credential-shaped run. */
function publicWord(s: string, charset: RegExp): boolean {
  return ENV_REFERENCE_RE.test(s) || (charset.test(s) && !credentialShaped(s));
}

const PATH_SEGMENT_CHARS = /^[A-Za-z0-9._~%+-]*$/;
const QUERY_VALUE_CHARS = /^[A-Za-z0-9._~%+:,/-]*$/;
const HOST_CHARS = /^[A-Za-z0-9._~%+:[\]-]*$/;
const NAME_CHARS = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;

/** User names a URL's userinfo carries that are a convention, not an
 *  identity or a secret (the password is the token). */
const CONVENTIONAL_USERS: ReadonlySet<string> = new Set([
  "__token__", "oauth2", "x-access-token", "x-token-auth", "x-oauth-basic", "gitlab-ci-token", "aws", "token", "git", "anonymous",
]);

/** A URL's user name that stays raw: a convention (`__token__`, `oauth2`),
 *  an environment reference, or a plain lowercase login (`alice`,
 *  `john.doe`, `ci-bot`, `user42`: letters and `._-`, at most four digits at
 *  the end, 28 characters at most). Anything else may be a token written as
 *  the user (`https://ghp_…:x-oauth-basic@github.com`) and is masked. */
function publicUser(u: string): boolean {
  return ENV_REFERENCE_RE.test(u) || CONVENTIONAL_USERS.has(u) || (u.length <= 28 && /^[a-z][a-z._-]*[0-9]{0,4}$/.test(u));
}

/**
 * The spans of one address token at absolute offset `at`: a URL
 * (`scheme://[user[:password]@]host[:port][/path][?query][#fragment]`) or a
 * scheme-less `[user[:password]@]host[:port]` or path. Masked: a password;
 * a user that is not `publicUser`; a path segment that is not word-like
 * (`PATH_SEGMENT_CHARS`, no credential-shaped run: Cloudsmith's
 * `/<token>/org/repo/`, GemFury's `/<token>/user/`); a query or fragment
 * value whose name looks secret or whose value is not word-like; a
 * scheme-less host that is not word-like unless `hostPublic` (pip's
 * `trusted-host`). A URL's scheme, host and port stay raw. Fields:
 * `<prefix>.<host>.user|password|path|query`, a secret-named query
 * parameter `<prefix>.<name>` (as before), a scheme-less word `wordKey`.
 *
 * `opts.percentUserinfo` (pip, which percent-decodes a URL's user and
 * password): a masked user or password is `encoded: "percent"`, its value
 * the decoded text, so the twin writes the percent-encoded token (plan 10
 * §11.13.1). `opts.wire` (pip's index URLs): on an `http(s)://` URL whose
 * host is a plain name or a bracketed IPv6 literal (`indexWireHost`), each
 * such span is also marked `wire` to that host[:port], which pip sends it
 * to inside HTTP Basic.
 */
function addressSpans(
  tok: string, at: number, prefix: string, wordKey: string, hostPublic = false,
  opts: { percentUserinfo?: boolean; wire?: boolean } = {},
): SecretSpan[] {
  const out: SecretSpan[] = [];
  const scheme = /^[a-z][a-z0-9+.-]*:\/\//i.exec(tok)?.[0] ?? "";
  const rest = tok.slice(scheme.length);
  const cut = rest.search(/[/?#]/);
  const authority = cut < 0 ? rest : rest.slice(0, cut);
  const atSign = authority.lastIndexOf("@");
  const hostport = authority.slice(atSign + 1);
  const host = fieldSegment(hostport.replace(/:[0-9]*$/, ""), "url");
  const wireHost = opts.wire && /^https?:\/\/$/i.test(scheme) ? indexWireHost(hostport) : null;
  const userinfo = (s: SecretSpan): SecretSpan => {
    if (!opts.percentUserinfo) return s;
    s.encoded = "percent";
    const plain = percentDecodeText(s.value);
    if (plain === null) return s; // not UTF-8 once decoded: never put back
    s.value = plain;
    // Put back only over the URL's own scheme: an https index's password
    // never in a plain-HTTP request (2026-10-03).
    if (wireHost !== null) s.wire = { host: wireHost, scheme: "basic", httpsOnly: !/^http:/i.test(scheme) };
    return s;
  };
  if (atSign >= 0) {
    const info = authority.slice(0, atSign);
    const colon = info.indexOf(":");
    const user = colon < 0 ? info : info.slice(0, colon);
    if (user !== "" && !publicUser(user)) out.push(userinfo(spanAt(`${prefix}.${host}.user`, at + scheme.length, user)));
    if (colon >= 0) {
      const pw = info.slice(colon + 1);
      if (pw !== "" && !ENV_REFERENCE_RE.test(pw)) out.push(userinfo(spanAt(`${prefix}.${host}.password`, at + scheme.length + colon + 1, pw)));
    }
  }
  if (scheme === "" && !hostPublic && hostport !== "" && !publicWord(hostport, HOST_CHARS)) {
    out.push(spanAt(wordKey, at + scheme.length + atSign + 1, hostport));
  }
  const pathAt = scheme.length + authority.length;
  const tail = tok.slice(pathAt);
  const q = tail.search(/[?#]/);
  const path = q < 0 ? tail : tail.slice(0, q);
  let off = pathAt;
  for (const seg of path.split("/")) {
    if (seg !== "" && !publicWord(seg, PATH_SEGMENT_CHARS)) out.push(spanAt(`${prefix}.${host}.path`, at + off, seg));
    off += seg.length + 1;
  }
  if (q >= 0) {
    const qAt = pathAt + q;
    const re = /[?#&;]([^?#&;]*)/g;
    const query = tok.slice(qAt);
    let m: RegExpExecArray | null;
    while ((m = re.exec(query)) !== null) {
      const item = m[1]!;
      const itemAt = at + qAt + m.index + 1;
      const eq = item.indexOf("=");
      if (eq < 0) {
        if (item !== "" && !publicWord(item, QUERY_VALUE_CHARS)) out.push(spanAt(`${prefix}.${host}.query`, itemAt, item));
        continue;
      }
      const name = item.slice(0, eq);
      const value = item.slice(eq + 1);
      if (name !== "" && !publicWord(name, NAME_CHARS)) out.push(spanAt(`${prefix}.${host}.query`, itemAt, name));
      if (value === "" || ENV_REFERENCE_RE.test(value)) continue;
      const secretName = isSecretKey(name);
      if (secretName || !publicWord(value, QUERY_VALUE_CHARS)) {
        const key = secretName && publicWord(name, NAME_CHARS) ? `${prefix}.${fieldSegment(name, "param")}` : `${prefix}.${host}.query`;
        out.push(spanAt(key, itemAt + eq + 1, value));
      }
    }
  }
  return out;
}

/** Every URL in free text (an ssh keyword's value), by `addressSpans`. */
function urlSpansInText(text: string, at: number, prefix: string): SecretSpan[] {
  const out: SecretSpan[] = [];
  const re = /\b[a-z][a-z0-9+.-]*:\/\/[^\s'"<>`]+/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) out.push(...addressSpans(m[0], at + m.index, prefix, `${prefix}.url`));
  return out;
}

/** The whole trimmed text of a line the extractor cannot read: in an
 *  exhaustive shape an unreadable line is masked (it might be anything). */
function wholeLineSpan(line: string, at: number, key: string): SecretSpan | null {
  const lead = line.length - line.trimStart().length;
  const value = line.trim();
  if (value === "") return null;
  return { key, start: at + lead, end: at + lead + value.length, value };
}

/** A comment line's text after its marker: no program reads it, so masking
 *  it costs a parser nothing, and a note (`# old password: …`) is not a
 *  place the extractor can vouch for. A marker with no letter or digit
 *  after it (a rule `#####`) stays. */
function commentSpan(line: string, at: number, key: string): SecretSpan | null {
  const m = /^(\s*[#;]+\s*)(.*?)\s*$/.exec(line);
  if (!m || !/[A-Za-z0-9]/.test(m[2]!)) return null;
  return spanAt(key, at + m[1]!.length, m[2]!);
}

/** The detection belt: every credential shape the content detector knows
 *  (`locateSecretShapes`, the scans' formats) in a line, wherever the
 *  rules above left it raw. Field `<prefix>.<shape>`. */
function detectorSpans(line: string, at: number, prefix: string): SecretSpan[] {
  return locateSecretShapes(line).map((s) => spanAt(`${prefix}.${s.shape}`, at + s.start, line.slice(s.start, s.end)));
}

/** `NAME=value` with a secret-looking name, anywhere in `text`: `SetEnv
 *  API_TOKEN=…`, `ProxyCommand env DB_PASSWORD=… nc %h %p`. The value
 *  (quotes kept outside the span) is the secret. */
function assignmentSpans(text: string, at: number, prefix: string): SecretSpan[] {
  const out: SecretSpan[] = [];
  const re = /(^|[\s;])([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const name = m[2]!;
    if (!isSecretKey(name) && !ENV_SECRET_NAME_RE.test(name)) continue;
    const { value, start } = stripQuotes(m[3]!, at + m.index + m[0].length - m[3]!.length);
    if (value === "" || ENV_REFERENCE_RE.test(value)) continue;
    out.push({ key: `${prefix}.${name}`, start, end: start + value.length, value });
  }
  return out;
}

/** A password given on a command line: `sshpass -p…`, `--password …`,
 *  `--token=…`. */
function commandPasswordSpans(text: string, at: number, prefix: string): SecretSpan[] {
  const out: SecretSpan[] = [];
  const re = /(\bsshpass\b(?:\s+-[^p\s]\S*)*\s+-p\s*|--(?:password|passwd|pass|token|secret|api-key)(?:=|\s+))("[^"]*"|'[^']*'|[^\s;]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const { value, start } = stripQuotes(m[2]!, at + m.index + m[1]!.length);
    if (value === "" || ENV_REFERENCE_RE.test(value)) continue;
    out.push({ key: `${prefix}.password`, start, end: start + value.length, value });
  }
  return out;
}

/** `finish` for the exhaustive shapes (and the list items of JSON, YAML
 *  and TOML): overlapping spans are MERGED (the union is masked) instead of
 *  the later one dropped, since several rules may claim one place. The
 *  union keeps every secret it covers as a part (`SecretSpan.parts`,
 *  2026-10-10): `--api-key key=https://u:PW@h` is one placeholder over the
 *  value, and `PW` is still a secret of its own, which a copy of it elsewhere in
 *  the file must not show. `withSettledParts` drops the parts that add
 *  nothing when the extraction returns. */
function finishMerged(shape: string, spans: SecretSpan[], content: string): SecretExtraction {
  if (spans.some((s) => s.key.length > MAX_FIELD_NAME)) return NONE; // see MAX_FIELD_NAME
  const seen = new Map<string, number>();
  for (const s of spans) {
    const n = (seen.get(s.key) ?? 0) + 1;
    seen.set(s.key, n);
    if (n > 1) s.key = `${s.key}__${n}`;
  }
  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  const out: SecretSpan[] = [];
  for (const s of spans) {
    const last = out[out.length - 1];
    if (last !== undefined && s.start < last.end) {
      // Taken before `last` grows: its own secret is the text it has now.
      // Appended in place (`out` holds copies): one union may cover many.
      last.parts ??= secretsOf(last);
      for (const p of secretsOf(s)) last.parts.push(p);
      if (s.end > last.end) {
        last.end = s.end;
        last.value = content.slice(last.start, last.end);
        // The union is no longer the value a program decodes or sends: it
        // twins as written and is never put back (§11.13.1).
        delete last.encoded;
        delete last.wire;
      }
      continue;
    }
    out.push(s.parts !== undefined ? { ...s, parts: [...s.parts] } : { ...s });
  }
  return { shape, spans: out };
}

/** Every secret `s` covers, as plain copies (a field name, a place, the
 *  value and its encoding): its parts once it has merged others (while an
 *  extraction runs they list all of them, its own first), else itself. */
function secretsOf(s: SecretSpan): SecretSpan[] {
  if (s.parts !== undefined) return s.parts;
  const p: SecretSpan = { key: s.key, start: s.start, end: s.end, value: s.value };
  if (s.encoded !== undefined) p.encoded = s.encoded;
  return [p];
}

/**
 * The extraction as it is returned: in each span that merged others, a part
 * that is the span's own secret (the same value, and the same encoding of
 * the same text) is left out, since the span holds it itself, and so is a
 * second part of the same secret. A remaining part keeps its field name
 * unless a span or an earlier part has it (a union keeps the field name of
 * its first secret, whose part then gives it up): then it is
 * `<name>__<n>`, as `finish` names a repeated key, with `n` the first
 * number no span or part has. A span left with no part has none. Pure.
 */
function withSettledParts(x: SecretExtraction, content: string): SecretExtraction {
  if (!x.spans.some((s) => s.parts !== undefined)) return x;
  const taken = new Set<string>();
  for (const s of x.spans) {
    taken.add(s.key);
    for (const p of s.parts ?? []) taken.add(p.key);
  }
  const claimed = new Set(x.spans.map((s) => s.key));
  const spans = x.spans.map((s): SecretSpan => {
    if (s.parts === undefined) return s;
    const { parts: all, ...span } = s;
    // A secret is its value in its encoding; an encoded one's file text is
    // a secret of its own too (the twin masks it, the registry mints it an
    // `.encoded` row), so a part whose value is that text adds nothing.
    const seen = new Set<string>();
    const secretIds = (t: SecretSpan): string[] => t.encoded === undefined
      ? [`${t.value}\u0000`]
      : [`${t.value}\u0000${t.encoded}\u0000${content.slice(t.start, t.end)}`, `${content.slice(t.start, t.end)}\u0000`];
    for (const id of secretIds(s)) seen.add(id);
    const parts: SecretSpan[] = [];
    for (const p of all) {
      const ids = secretIds(p);
      if (p.value === "" || seen.has(ids[0]!)) continue;
      for (const id of ids) seen.add(id);
      let key = p.key;
      if (claimed.has(key)) {
        let n = 2;
        while (taken.has(`${p.key}__${n}`)) n++;
        key = `${p.key}__${n}`;
        taken.add(key);
      }
      claimed.add(key);
      parts.push({ ...p, key });
    }
    return parts.length > 0 ? { ...span, parts } : span;
  });
  return { shape: x.shape, spans };
}

// ── ssh_config ──────────────────────────────────────────────────────────────

/** ssh_config(5) keywords (OpenSSH 10.2, plus older names ssh still
 *  accepts and the macOS `UseKeychain`), lowercased. A line whose keyword is
 *  not one of these is masked whole: ssh refuses an unknown keyword, so the
 *  mask costs nothing there, and an unknown line is not one whose contents
 *  we can vouch for. Under `IgnoreUnknown` (ssh skips the keyword) the name
 *  stays and the value is masked. */
const SSH_CONFIG_KEYWORDS: ReadonlySet<string> = new Set((
  "host match include ignoreunknown addkeystoagent addressfamily batchmode bindaddress bindinterface " +
  "canonicaldomains canonicalizefallbacklocal canonicalizehostname canonicalizemaxdots canonicalizepermittedcnames " +
  "casignaturealgorithms certificatefile channeltimeout challengeresponseauthentication checkhostip cipher ciphers " +
  "clearallforwardings compression compressionlevel connectionattempts connecttimeout controlmaster controlpath " +
  "controlpersist dynamicforward enableescapecommandline enablesshkeysign escapechar exitonforwardfailure " +
  "fingerprinthash forkafterauthentication forwardagent forwardx11 forwardx11timeout forwardx11trusted gatewayports " +
  "globalknownhostsfile gssapiauthentication gssapiclientidentity gssapidelegatecredentials gssapikexalgorithms " +
  "gssapikeyexchange gssapirenewalforcesrekey gssapiserveridentity gssapitrustdns hashknownhosts " +
  "hostbasedacceptedalgorithms hostbasedauthentication hostbasedkeytypes hostkeyalgorithms hostkeyalias hostname " +
  "identitiesonly identityagent identityfile ipqos kbdinteractiveauthentication kbdinteractivedevices kexalgorithms " +
  "knownhostscommand localcommand localforward loglevel logverbose macs nohostauthenticationforlocalhost " +
  "numberofpasswordprompts obscurekeystroketiming passwordauthentication permitlocalcommand permitremoteopen " +
  "pkcs11provider port preferredauthentications protocol proxycommand proxyjump proxyusefdpass " +
  "pubkeyacceptedalgorithms pubkeyacceptedkeytypes pubkeyauthentication refuseconnection rekeylimit remotecommand " +
  "remoteforward requesttty requiredrsasize revokedhostkeys securitykeyprovider sendenv serveralivecountmax " +
  "serveraliveinterval sessiontype setenv smartcarddevice stdinnull streamlocalbindmask streamlocalbindunlink " +
  "stricthostkeychecking syslogfacility tag tcpkeepalive tunnel tunneldevice updatehostkeys usekeychain user " +
  "userknownhostsfile verifyhostkeydns versionaddendum visualhostkey warnweakcrypto xauthlocation"
).split(" "));

/** Keywords whose value is a command ssh runs (or sends to the server).
 *  `ProxyCommand` stays raw under the relay grammar (`proxyCommandSafe`);
 *  the others only as `none`: their commands are anyone's. */
const SSH_COMMAND_KEYWORDS: ReadonlySet<string> = new Set(["proxycommand", "localcommand", "remotecommand", "knownhostscommand"]);

/** Every other keyword's value is public by the format: a host, a user, a
 *  port, a file path, a flag, an algorithm list, a forwarding rule. It stays
 *  raw (with the URL, assignment and password-flag belts). Keywords an
 *  `ssh -o` in a vetted command may set: these, minus the ones that run or
 *  pull in something. */
const SSH_OPTION_EXCLUDED: ReadonlySet<string> = new Set([...SSH_COMMAND_KEYWORDS, "setenv", "match", "host", "include", "permitlocalcommand"]);

/** A word of shell syntax ProxyCommand's `sh -c` would act on: a pipe, a
 *  redirection, a list, a substitution, a glob, an escape, a comment. */
const SHELL_SYNTAX = /[|&;<>()$`\\*?!{}[\]#]/;

/** The plain words of a command, or null when it uses any shell syntax (a
 *  quoted word is one word; a double-quoted one with `$`, a backquote or a
 *  backslash is syntax). */
function shellWords(cmd: string): string[] | null {
  const out: string[] = [];
  let i = 0;
  while (i < cmd.length) {
    while (i < cmd.length && /\s/.test(cmd[i]!)) i++;
    if (i >= cmd.length) break;
    let w = "";
    while (i < cmd.length && !/\s/.test(cmd[i]!)) {
      const c = cmd[i]!;
      if (c === "'" || c === '"') {
        const close = cmd.indexOf(c, i + 1);
        if (close < 0) return null;
        const inner = cmd.slice(i + 1, close);
        if (c === '"' && /[$`\\]/.test(inner)) return null;
        w += inner;
        i = close + 1;
      } else {
        if (SHELL_SYNTAX.test(c)) return null;
        w += c;
        i++;
      }
    }
    out.push(w);
  }
  return out;
}

/** An argument of a vetted command: a host, a port, a path, a `%`-token,
 *  `user@host`, `key=value`; no credential-shaped run. */
function publicArg(w: string): boolean {
  return /^[A-Za-z0-9%._~/:@,=+-]+$/.test(w) && !credentialShaped(w);
}

/** `ssh -o Key=Value` (or `Key Value`): a public keyword with public words. */
function sshOptionSafe(arg: string): boolean {
  const m = /^([A-Za-z][A-Za-z0-9]*)(?:\s*=\s*|\s+)(.*)$/.exec(arg.trim());
  if (!m) return false;
  const kw = m[1]!.toLowerCase();
  if (!SSH_CONFIG_KEYWORDS.has(kw) || SSH_OPTION_EXCLUDED.has(kw)) return false;
  return m[2]!.split(/\s+/).every((w) => w === "" || publicArg(w));
}

/** One relay program's command line, as far as a vetted ProxyCommand may
 *  use it: options without (`flags0`) and with (`flags1`) a value, the
 *  positional arguments it takes, a fixed subcommand, and a check for each
 *  positional (default `publicArg`). Credential options (`ncat
 *  --proxy-auth`, `nc -P`, `cloudflared --service-token-secret`, socat's
 *  `proxyauth=`) and code options (`ncat -e`, `--sh-exec`) are on no list,
 *  so a command using one is masked. */
interface RelayGrammar {
  flags0: ReadonlySet<string>;
  flags1: ReadonlySet<string>;
  maxPositional: number;
  sub?: readonly string[];
  positional?: (w: string) => boolean;
}
const chars = (s: string): string[] => s.split("").map((c) => `-${c}`);
const SOCAT_ADDRESS_TYPES: ReadonlySet<string> = new Set([
  "STDIO", "STDIN", "STDOUT", "TCP", "TCP4", "TCP6", "TCP-CONNECT", "TCP4-CONNECT", "TCP6-CONNECT", "PROXY", "PROXY-CONNECT",
  "SOCKS4", "SOCKS4A", "SOCKS5", "SOCKS5-CONNECT", "OPENSSL", "OPENSSL-CONNECT", "UNIX-CONNECT", "UNIX-CLIENT",
]);
const SOCAT_OPTIONS: ReadonlySet<string> = new Set([
  "proxyport", "socksport", "connect-timeout", "retry", "interval", "forever", "nodelay", "keepalive", "verify", "cafile",
  "commonname", "snihost", "bind", "sourceport", "sp",
]);
/** A socat address: `-`, or a known connecting type with public parameters
 *  and only connection options (no `proxyauth=`, no `exec`/`system`). */
function socatAddressSafe(spec: string): boolean {
  if (spec === "-") return true;
  const [head, ...opts] = spec.split(",");
  const params = head!.split(":");
  if (!SOCAT_ADDRESS_TYPES.has(params[0]!.toUpperCase())) return false;
  if (!params.slice(1).every((p) => p === "" || publicArg(p))) return false;
  return opts.every((o) => {
    const eq = o.indexOf("=");
    const k = (eq < 0 ? o : o.slice(0, eq)).toLowerCase();
    return SOCAT_OPTIONS.has(k) && (eq < 0 || publicArg(o.slice(eq + 1)));
  });
}
const NC: RelayGrammar = { flags0: new Set(chars("46Nnvzd")), flags1: new Set([...chars("XxwqspIOiT"), "--proxy", "--proxy-type", "--proxy-dns"]), maxPositional: 2 };
const RELAYS: ReadonlyMap<string, RelayGrammar> = new Map<string, RelayGrammar>([
  ["nc", NC], ["ncat", NC], ["netcat", NC], ["nc.openbsd", NC], ["nc.traditional", NC],
  ["connect", { flags0: new Set(chars("45d")), flags1: new Set(chars("HSRTwp")), maxPositional: 2 }],
  ["connect-proxy", { flags0: new Set(chars("45d")), flags1: new Set(chars("HSRTwp")), maxPositional: 2 }],
  ["corkscrew", { flags0: new Set(), flags1: new Set(), maxPositional: 5 }],
  ["socat", { flags0: new Set(chars("dvuUhxlsg")), flags1: new Set(chars("Ttb")), maxPositional: 2, positional: socatAddressSafe }],
  ["cloudflared", { flags0: new Set(), flags1: new Set(["--hostname", "--url", "--destination", "--loglevel", "--logfile"]), maxPositional: 0, sub: ["access", "ssh"] }],
  ["aws", {
    flags0: new Set(["--no-cli-pager"]),
    flags1: new Set(["--target", "--document-name", "--parameters", "--region", "--profile", "--reason", "--endpoint-url"]),
    maxPositional: 0, sub: ["ssm", "start-session"],
  }],
  ["gcloud", {
    flags0: new Set(["--listen-on-stdin"]),
    flags1: new Set(["--project", "--zone", "--region", "--network", "--dest-group", "--local-host-port", "--verbosity", "--configuration"]),
    maxPositional: 2, sub: ["compute", "start-iap-tunnel"],
  }],
]);

/** Does a relay program's argument list follow its grammar? */
function relayArgsSafe(g: RelayGrammar, words: readonly string[]): boolean {
  let positional = 0;
  let sub = 0;
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    if (g.sub !== undefined && sub < g.sub.length) {
      if (w !== g.sub[sub]) return false;
      sub++;
      continue;
    }
    if (w.startsWith("--")) {
      const eq = w.indexOf("=");
      const name = eq < 0 ? w : w.slice(0, eq);
      if (g.flags0.has(name) && eq < 0) continue;
      if (!g.flags1.has(name)) return false;
      const v = eq < 0 ? words[++i] : w.slice(eq + 1);
      if (v === undefined || !publicArg(v)) return false;
      continue;
    }
    if (w.startsWith("-") && w.length > 1) {
      for (let k = 1; k < w.length; k++) {
        const f = `-${w[k]}`;
        if (g.flags0.has(f)) continue;
        if (!g.flags1.has(f)) return false;
        const v = k + 1 < w.length ? w.slice(k + 1) : words[++i];
        if (v === undefined || !publicArg(v)) return false;
        break;
      }
      continue;
    }
    if (++positional > g.maxPositional) return false;
    if (!(g.positional ?? publicArg)(w)) return false;
  }
  return g.sub === undefined || sub === g.sub.length;
}

const SSH_FLAGS0 = new Set("46AaCfGgKkMNnqsTtVvXxYy".split(""));
const SSH_FLAGS1 = new Set("BbcDEeFIiJLlmOoPpQRSWw".split(""));

/** `ssh [options] destination [relay command]`: options from ssh's own
 *  list with public values (`-o` a public keyword), one destination, and
 *  after it (ssh stops parsing options there) nothing or a relay program's
 *  vetted command (`ssh bastion nc %h %p`). */
function sshArgsSafe(words: readonly string[]): boolean {
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    if (w.startsWith("-") && w.length > 1) {
      for (let k = 1; k < w.length; k++) {
        const f = w[k]!;
        if (SSH_FLAGS0.has(f)) continue;
        if (!SSH_FLAGS1.has(f)) return false;
        const v = k + 1 < w.length ? w.slice(k + 1) : words[++i];
        if (v === undefined || !(f === "o" ? sshOptionSafe(v) : publicArg(v))) return false;
        break;
      }
      continue;
    }
    if (!publicArg(w)) return false;
    const rest = words.slice(i + 1);
    return rest.length === 0 || relayCommandSafe(rest);
  }
  return false;
}

/** A relay program (not ssh) and its vetted arguments. */
function relayCommandSafe(words: readonly string[]): boolean {
  const prog = words[0];
  if (prog === undefined || (prog.includes("/") && !publicArg(prog))) return false;
  const g = RELAYS.get(prog.slice(prog.lastIndexOf("/") + 1));
  return g !== undefined && relayArgsSafe(g, words.slice(1));
}

/** Plan 10 §11.13.2: may this ProxyCommand (or `Match exec` command) stay
 *  raw in the twin? Only a plain word list (no shell syntax), optionally
 *  after `exec`, running ssh or a known relay (`nc`, `ncat`, `socat`,
 *  `connect-proxy`, `corkscrew`, `cloudflared access ssh`, `aws ssm
 *  start-session`, `gcloud compute start-iap-tunnel`) with options from its
 *  grammar and public arguments. Anything else is masked whole. Pure. */
export function proxyCommandSafe(cmd: string): boolean {
  let words = shellWords(cmd);
  if (words === null) return false;
  if (words[0] === "exec") words = words.slice(1);
  const prog = words[0];
  if (prog === undefined) return false;
  if (prog.slice(prog.lastIndexOf("/") + 1) === "ssh") return (!prog.includes("/") || publicArg(prog)) && sshArgsSafe(words.slice(1));
  return relayCommandSafe(words);
}

/** A config word as ssh splits one (`argv_split`): its raw extent and its
 *  unquoted text, with each unquoted character's raw offset. */
interface ConfigWord { start: number; end: number; text: string; at: number[] }

function configWords(s: string): ConfigWord[] | null {
  const out: ConfigWord[] = [];
  let i = 0;
  while (i < s.length) {
    while (i < s.length && /\s/.test(s[i]!)) i++;
    if (i >= s.length) break;
    const start = i;
    let text = "";
    const at: number[] = [];
    while (i < s.length && !/\s/.test(s[i]!)) {
      const c = s[i]!;
      if (c === '"' || c === "'") {
        const close = s.indexOf(c, i + 1);
        if (close < 0) return null;
        for (let j = i + 1; j < close; j++) { text += s[j]; at.push(j); }
        i = close + 1;
      } else {
        text += c;
        at.push(i);
        i++;
      }
    }
    out.push({ start, end: i, text, at });
  }
  return out;
}

/** A withheld command (plan 10 §11.13.3): its span covers the whole
 *  command, and the twin writes Mandu's refusal command in its place
 *  (`withheldCommandTwin`), so the host fails loudly, saying where and why,
 *  never silently and never with the command's text. */
function commandSpan(key: string, start: number, value: string, withheld: WithheldCommand): SecretSpan {
  return { ...spanAt(key, start, value), withheld };
}

/** The file as a withheld command's message names it: from `/.ssh/` on as
 *  `~/.ssh/…` (the user's name stays out of a `RemoteCommand` the server
 *  sees), every character outside a plain path's set replaced, so the name
 *  can sit unquoted in a shell word and ssh's `%` expansion finds nothing. */
export function withheldFileName(path: string): string {
  const i = path.lastIndexOf("/.ssh/");
  const shown = i >= 0 ? `~${path.slice(i)}` : path.slice(path.lastIndexOf("/") + 1);
  return shown.replace(/[^A-Za-z0-9._/~+-]/g, "_").slice(0, 200) || "ssh_config";
}

/** What withholding each kind of command does to ssh. */
const WITHHELD_EFFECT: Readonly<Record<string, string>> = {
  ProxyCommand: "so ssh cannot reach this host from inside the agent",
  RemoteCommand: "so a session to this host ends at once",
  LocalCommand: "so ssh runs this notice in its place",
  KnownHostsCommand: "so ssh cannot check the key of this host from inside the agent",
  "Match exec": "so this Match block is skipped",
};

/**
 * What a withheld ssh command says when ssh runs it (plan 10 §11.13.3): the
 * file, the line, the keyword, why, and the way out. Pure, and built from
 * the three facts only: the command's text (which may hold the secret) is
 * never an input. Every line is shell-inert (no quote, `$`, backquote,
 * backslash, glob or `%`): it is passed as one single-quoted argument and
 * printed through an unquoted expansion under `set -f`.
 */
export function withheldCommandMessage(w: Pick<WithheldCommand, "file" | "line" | "keyword">): string[] {
  const where = `${w.file} line ${w.line}`;
  const effect = WITHHELD_EFFECT[w.keyword] ?? "so ssh runs this notice in its place";
  return [
    `mandu: ${where}: ${w.keyword} withheld from the programs the agent runs, ${effect}.`,
    "mandu: why: Mandu cannot vouch for this command. Its text may hold a secret, and running it would run code holding one. The command is not shown.",
    `mandu: way out: use ProxyJump or plain ssh -W; or move the command into a script Mandu can pin and let ssh read the real file (mandu why ${w.file} shows how); or run this ssh outside the agent.`,
  ];
}

/** The twin's text for a withheld command: `/bin/sh -c` printing the
 *  message to standard error and exiting 1, every argument single-quoted
 *  (the field symbol is `$0`, unused), so it runs the same as a
 *  `ProxyCommand` (`sh -c "exec …"`), a `LocalCommand` or `Match exec`
 *  (`sh -c`), a `KnownHostsCommand` (ssh's own word split) and a
 *  `RemoteCommand` (the server's shell). A `Match exec` word is
 *  double-quoted around it, with no double quote inside. */
export function withheldCommandTwin(w: WithheldCommand, token: string): string {
  const q = (x: string): string => `'${x.replace(/'/g, "")}'`;
  const cmd = ["/bin/sh", "-c", q("set -f; for l; do echo $l; done >&2; exit 1"), q(token), ...withheldCommandMessage(w).map(q)].join(" ");
  return w.quote ? `"${cmd}"` : cmd;
}

/** `SetEnv NAME=value …`: every value is masked whatever its name (the
 *  remote side gets the symbol), an environment reference excepted; a word
 *  that is not `NAME=value`, or whose name is not a plain name, is masked
 *  whole. */
function setEnvSpans(rest: string, restAt: number, block: string): SecretSpan[] {
  const words = configWords(rest);
  if (words === null) {
    const s = wholeLineSpan(rest, restAt, `${block}.SetEnv`);
    return s ? [s] : [];
  }
  const out: SecretSpan[] = [];
  for (const w of words) {
    const eq = w.text.indexOf("=");
    const name = eq < 0 ? "" : w.text.slice(0, eq);
    if (eq < 0 || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || credentialShaped(name)) {
      out.push(spanAt(`${block}.SetEnv`, restAt + w.start, rest.slice(w.start, w.end)));
      continue;
    }
    const value = w.text.slice(eq + 1);
    if (value === "" || ENV_REFERENCE_RE.test(value)) continue;
    const a = w.at[eq + 1]!;
    const b = w.at[w.text.length - 1]! + 1;
    out.push(spanAt(`${block}.${name}`, restAt + a, rest.slice(a, b)));
  }
  return out;
}

/** `Match` criteria that take an argument, and those that take none. */
const MATCH_ARG: ReadonlySet<string> = new Set(["exec", "localnetwork", "host", "originalhost", "tagged", "command", "user", "localuser", "version", "sessiontype"]);
const MATCH_BARE: ReadonlySet<string> = new Set(["all", "canonical", "final"]);

/** `Match …`: the block's field name comes from its `host` (or
 *  `originalhost`) pattern, never from an `exec` command; an `exec`
 *  command stays raw only under the relay grammar, else its whole word is
 *  withheld (the twin writes Mandu's refusal there, one double-quoted word,
 *  plan 10 §11.13.3); an unknown criterion masks the rest of
 *  the line (ssh refuses it anyway). */
function matchSpans(rest: string, restAt: number, where: { file: string; line: number }): { block: string; spans: SecretSpan[] } {
  const words = configWords(rest);
  if (words === null) {
    const s = wholeLineSpan(rest, restAt, "match.line");
    return { block: "match", spans: s ? [s] : [] };
  }
  let block = "match";
  for (let i = 0; i + 1 < words.length; i++) {
    const c = words[i]!.text.toLowerCase().replace(/^!/, "");
    if (c === "host" || c === "originalhost") { block = fieldSegment(words[i + 1]!.text.split(",").pop() ?? "", "match"); break; }
  }
  const spans: SecretSpan[] = [];
  for (let i = 0; i < words.length; i++) {
    const c = words[i]!.text.toLowerCase().replace(/^!/, "");
    if (MATCH_BARE.has(c)) continue;
    const arg = words[i + 1];
    if (!MATCH_ARG.has(c) || arg === undefined) {
      const tailText = rest.slice(words[i]!.start).replace(/\s+$/, "");
      spans.push(spanAt(`${block}.match`, restAt + words[i]!.start, tailText));
      break;
    }
    i++;
    if (c !== "exec" || proxyCommandSafe(arg.text) || arg.text === "") continue;
    // The whole word, its quotes included: the twin writes one
    // double-quoted word of its own there.
    spans.push(commandSpan(`${block}.exec`, restAt + arg.start, rest.slice(arg.start, arg.end), { ...where, keyword: "Match exec", quote: true }));
  }
  return { block, spans };
}

/** An `IgnoreUnknown` pattern list as one test. */
function sshPatternTest(patterns: readonly string[]): (kw: string) => boolean {
  const res = patterns.map((p) => new RegExp(`^${p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`, "i"));
  return (kw) => res.some((r) => r.test(kw));
}

/** A command keyword as ssh_config(5) spells it, for the message. */
const SSH_COMMAND_NAMES: Readonly<Record<string, string>> = {
  proxycommand: "ProxyCommand", localcommand: "LocalCommand", remotecommand: "RemoteCommand", knownhostscommand: "KnownHostsCommand",
};

/**
 * `~/.ssh/config` (and an `Include`d `~/.ssh/config.d/*`). FAIL CLOSED
 * (plan 10 §11.13.2): a value stays raw only where the format makes it
 * public, keyword by keyword:
 *   - a keyword whose value is a host, a user, a port, a file path, a flag,
 *     an algorithm list or a forwarding rule (every keyword not below):
 *     raw, with the URL (`addressSpans`), `NAME=value` and password-flag
 *     belts. Keywords are NOT judged by name: `PubkeyAuthentication yes`
 *     must stay `yes`, or ssh refuses the file;
 *   - `ProxyCommand`: raw when `none` or when `proxyCommandSafe` vouches
 *     for it (ssh or a known relay with public arguments), else withheld
 *     whole; `LocalCommand`, `RemoteCommand`, `KnownHostsCommand`: raw
 *     only as `none`; a `Match exec` command as `ProxyCommand`. A withheld
 *     command's span carries its line and keyword (`withheld`), and the twin
 *     writes in its place a command of Mandu's own that prints which line
 *     of which file was withheld, why, and the way out, then fails
 *     (§11.13.3); the field symbol rides along unused;
 *   - `SetEnv`: every value masked whatever the name;
 *   - an unknown keyword: the whole line (ssh refuses it), or its value
 *     when `IgnoreUnknown` names it; a line that is not `Keyword value`:
 *     masked whole; a comment's text: masked.
 * The content detector's credential shapes are masked wherever they sit.
 */
function extractSshConfig(content: string, path: string): SecretExtraction {
  const file = withheldFileName(path);
  const spans: SecretSpan[] = [];
  const belt: SecretSpan[] = []; // the detector belt, after the specific rules (their field names win a merge)
  const ignored: string[] = [];
  for (const { line } of lines(content)) {
    const m = /^\s*ignoreunknown(?:\s*=\s*|\s+)(.*)$/i.exec(line);
    if (m) ignored.push(...m[1]!.split(/[\s,]+/).filter((p) => p !== ""));
  }
  const isIgnored = sshPatternTest(ignored);
  let block = "global";
  let lineNo = 0;
  for (const { line, at } of lines(content)) {
    lineNo++;
    if (/^\s*$/.test(line)) continue;
    if (/^\s*#/.test(line)) {
      const s = commentSpan(line, at, `${block}.comment`);
      if (s) spans.push(s);
      continue;
    }
    belt.push(...detectorSpans(line, at, block));
    const m = /^(\s*)([A-Za-z][A-Za-z0-9]*)(\s*=\s*|\s+)(.*)$/.exec(line);
    const kw = m?.[2]!.toLowerCase();
    if (!m || kw === undefined || !SSH_CONFIG_KEYWORDS.has(kw)) {
      const kept = m !== null && kw !== undefined && isIgnored(kw) && !credentialShaped(m[2]!);
      const s = kept ? wholeLineSpan(m![4]!, at + line.length - m![4]!.length, `${block}.${fieldSegment(m![2]!, "line")}`) : wholeLineSpan(line, at, `${block}.line`);
      if (s) spans.push(s);
      continue;
    }
    const rest = m[4]!;
    const restAt = at + line.length - rest.length;
    if (kw === "match") {
      const r = matchSpans(rest, restAt, { file, line: lineNo });
      block = r.block;
      spans.push(...r.spans);
      continue;
    }
    if (kw === "host") block = fieldSegment(rest.trim().split(/\s+/).pop() ?? "", "host");
    if (kw === "setenv") { spans.push(...setEnvSpans(rest, restAt, block)); continue; }
    if (SSH_COMMAND_KEYWORDS.has(kw)) {
      const value = rest.replace(/\s+$/, "");
      if (value === "" || value.toLowerCase() === "none" || (kw === "proxycommand" && proxyCommandSafe(value))) continue;
      spans.push(commandSpan(`${block}.${fieldSegment(m[2]!, "command")}`, restAt, value, { file, line: lineNo, keyword: SSH_COMMAND_NAMES[kw]! }));
      continue;
    }
    spans.push(...urlSpansInText(rest, restAt, block));
    spans.push(...assignmentSpans(rest, restAt, block));
    spans.push(...commandPasswordSpans(rest, restAt, block));
  }
  return finishMerged("ssh-config", [...spans, ...belt], content);
}

// ── pip.conf ────────────────────────────────────────────────────────────────

/** The sections pip reads: `[global]` and one per pip command. A key in
 *  any other section never reaches pip, so its value is masked at no cost. */
const PIP_SECTIONS: ReadonlySet<string> = new Set([
  "global", "install", "download", "wheel", "uninstall", "freeze", "list", "show", "check", "config", "search", "cache",
  "index", "hash", "inspect", "debug", "completion", "help", "lock",
]);

/** pip's configuration keys (its long option names, normalized as pip
 *  does: lowercase, `_` → `-`, no leading `--`). A known key's value is
 *  read word by word (`addressSpans`); any other key's value is masked. */
const PIP_KEYS: ReadonlySet<string> = new Set((
  // general options
  "isolated python require-virtualenv verbose version quiet log log-file no-input keyring-provider proxy retries " +
  "timeout default-timeout exists-action trusted-host cert client-cert cache-dir no-cache-dir disable-pip-version-check " +
  "no-color no-python-version-warning use-feature use-deprecated resume-retries progress-bar " +
  // package index options
  "index-url extra-index-url no-index find-links " +
  // install / download / wheel
  "requirement constraint editable target platform python-version implementation abi user root prefix src upgrade " +
  "upgrade-strategy force-reinstall ignore-installed ignore-requires-python no-build-isolation use-pep517 no-use-pep517 " +
  "check-build-dependencies break-system-packages compile no-compile no-warn-script-location no-warn-conflicts " +
  "no-binary only-binary prefer-binary require-hashes root-user-action report no-deps pre dry-run no-clean dest " +
  "wheel-dir no-verify group " +
  // list / freeze / uninstall / config / cache / hash / show
  "outdated uptodate local path format not-required exclude-editable include-editable exclude all yes editor global " +
  "site algorithm files"
).split(" "));

/** Known keys whose value is free text handed to a build backend: masked
 *  whole, like an unknown key. */
const PIP_FREE_TEXT_KEYS: ReadonlySet<string> = new Set(["config-settings", "global-option", "build-option", "install-option"]);

const pipKeyName = (key: string): string => key.toLowerCase().replace(/_/g, "-").replace(/^--/, "");

/**
 * `pip.conf` / `pip.ini` (RawConfigParser, what pip reads). FAIL CLOSED
 * (plan 10 §11.13.2): a known pip key in a section pip reads has its value
 * read word by word (`addressSpans`: a URL's password, a user that is not a
 * plain login, a path segment or query value shaped like a credential, a
 * scheme-less `user:password@proxy`; `trusted-host` words are hosts); its
 * continuation lines the same. Any other key (a plugin's setting, a key in
 * a section pip never reads, a build backend's free text) has its value
 * and continuation lines masked, and its name too when the name is not a
 * plain name. A comment's text, and a line that is none of section,
 * comment, `key = value` or continuation, are masked. The content
 * detector's credential shapes are masked wherever they sit.
 *
 * Plan 10 §11.13.1 (2026-10-03): a URL's masked user or password is
 * `encoded: "percent"` (the twin writes the percent-encoded token, which pip
 * decodes back into the token), and in an `index-url` / `extra-index-url`
 * on `http(s)://` with a plain host it is marked `wire` to that host, where
 * pip sends it inside HTTP Basic and the session proxy puts it back.
 */
function extractPipConf(content: string): SecretExtraction {
  const spans: SecretSpan[] = [];
  const belt: SecretSpan[] = [];
  let section = "pip";
  let sectionKnown = true;
  let inKey: { field: string; words: boolean; hostPublic: boolean; wire: boolean } | null = null;
  // Every URL user and password is percent-encoded in the twin (pip
  // percent-decodes them; a raw token's brackets break Python's URL
  // parser), and an index URL's are marked for the wire (§11.13.1).
  const words = (text: string, at: number, k: { field: string; hostPublic: boolean; wire: boolean }): void => {
    const re = /\S+/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      spans.push(...addressSpans(m[0], at + m.index, section, k.field, k.hostPublic, { percentUserinfo: true, wire: k.wire }));
    }
  };
  for (const { line, at } of lines(content)) {
    if (/^\s*$/.test(line)) continue;
    if (/^\s*[#;]/.test(line)) {
      const s = commentSpan(line, at, `${section}.comment`);
      if (s) spans.push(s);
      continue;
    }
    belt.push(...detectorSpans(line, at, section));
    const sec = INI_SECTION.exec(line);
    if (sec && !/^\s/.test(line)) {
      const name = sec[1]!.trim();
      sectionKnown = PIP_SECTIONS.has(name.toLowerCase());
      if (publicWord(name, NAME_CHARS)) {
        section = fieldSegment(name, "section");
      } else {
        section = "section";
        const a = at + line.indexOf(name);
        spans.push(spanAt("section", a, name));
      }
      inKey = null;
      continue;
    }
    if (/^\s/.test(line) && inKey !== null) {
      // A continuation line of the previous key's value (RawConfigParser).
      if (inKey.words) words(line, at, inKey);
      else {
        const s = wholeLineSpan(line, at, inKey.field);
        if (s) spans.push(s);
      }
      continue;
    }
    const m = /^(\s*)([^=:\s][^=:]*?)(\s*[=:]\s*)(.*)$/.exec(line);
    if (!m) {
      const s = wholeLineSpan(line, at, `${section}.line`);
      if (s) spans.push(s);
      inKey = null;
      continue;
    }
    const key = m[2]!.trim();
    const norm = pipKeyName(key);
    const known = sectionKnown && PIP_KEYS.has(norm) && !PIP_FREE_TEXT_KEYS.has(norm);
    let field: string;
    if (known || publicWord(key, NAME_CHARS)) {
      field = `${section}.${fieldSegment(key, "key")}`;
    } else {
      spans.push(spanAt(`${section}.key`, at + m[1]!.length, key));
      field = `${section}.value`;
    }
    inKey = { field, words: known, hostPublic: norm === "trusted-host", wire: norm === "index-url" || norm === "extra-index-url" };
    const valueAt = at + m[1]!.length + m[2]!.length + m[3]!.length;
    const value = m[4]!.replace(/\s+$/, "");
    if (value === "") continue;
    if (known) words(value, valueAt, inKey);
    else spans.push(spanAt(field, valueAt, value));
  }
  return finishMerged("pip-conf", [...spans, ...belt], content);
}

// ── git's credential store ──────────────────────────────────────────────────

/**
 * `~/.git-credentials` / `$XDG_CONFIG_HOME/git/credentials` (git's `store`
 * helper): one URL per line, `https://user:password@host[/path]`. FAIL
 * CLOSED (plan 10 §11.13.2): a line that is not exactly one URL is masked
 * whole (git writes nothing else, and has no comment syntax); in a URL the
 * password is masked, the user unless it is a plain login or a convention
 * (`oauth2`), and a path segment or query value shaped like a credential.
 * git itself is a known consumer (flow-taint.ts CONSUMER_TABLE) and, a
 * printer since 2026-10-04 (plan 13 §4.9), reads this twin too: under the
 * wire release the session proxy puts the password back at its host.
 */
function extractGitCredentials(content: string): SecretExtraction {
  const spans: SecretSpan[] = [];
  const belt: SecretSpan[] = [];
  for (const { line, at } of lines(content)) {
    if (line.trim() === "") continue;
    const m = /^(\s*)([a-z][a-z0-9+.-]*:\/\/\S+)\s*$/i.exec(line);
    if (!m) {
      const s = wholeLineSpan(line, at, "line");
      if (s) spans.push(s);
      continue;
    }
    spans.push(...addressSpans(m[2]!, at + m[1]!.length, "git", "git.value"));
    belt.push(...detectorSpans(line, at, "git"));
  }
  return finishMerged("git-credentials", [...spans, ...belt], content);
}

/** The shapes whose extractor reads every place the format can hold a
 *  secret (and masks what it cannot read): an extraction with no span means
 *  the file holds no secret, and its twin is its own text. */
const EXHAUSTIVE_SHAPES: ReadonlySet<string> = new Set(["ssh-config", "pip-conf", "git-credentials"]);

/** Is a zero-span extraction of this shape the whole truth (twin = the
 *  file's text) rather than a miss (whole-file twin)? */
export function shapeIsExhaustive(shape: string | null): boolean {
  return shape !== null && EXHAUSTIVE_SHAPES.has(shape);
}

// ── dispatch ────────────────────────────────────────────────────────────────

/** Which shape a path has, by basename and parent; null = whole-file twin. */
export function secretFileShape(path: string): string | null {
  const parts = path.split("/");
  const base = parts[parts.length - 1] ?? "";
  const parent = parts[parts.length - 2] ?? "";
  if (base === ".env" || base.startsWith(".env.") || base.endsWith(".env") || base === ".envrc") return "dotenv";
  if (base === ".pgpass") return "pgpass";
  if (base === ".netrc" || base === "_netrc") return "netrc";
  if (base === ".npmrc") return "npmrc";
  if (base === ".pypirc") return "ini";
  if (base === ".git-credentials" || (parent === "git" && base === "credentials")) return "git-credentials";
  if (base === "pip.conf" || base === "pip.ini") return "pip-conf";
  if ((parent === ".ssh" && base === "config") || (/^conf(ig)?\.d$/.test(parent) && parts[parts.length - 3] === ".ssh")) return "ssh-config";
  if (/credentials$/i.test(base) && !/\.(json|ya?ml)$/i.test(base)) return "ini";
  if (parent === ".aws" && base === "config") return "ini";
  if (parent === ".kube" && base === "config") return "yaml-keys";
  if ([".my.cnf", ".boto", ".s3cfg", ".databrickscfg", ".sentryclirc"].includes(base)) return "ini";
  // `.cnf` (2026-10-19, secret-discovery.md §2.9): MySQL's and MariaDB's
  // option files (`my.cnf`, `client.cnf`), INI as `.my.cnf` is.
  if (/\.(properties|ini|cfg|conf|cnf)$/i.test(base)) return "ini";
  if (/\.(toml|tfvars)$/i.test(base)) return "toml";
  if (/\.(xml|config)$/i.test(base)) return "xml-keys";
  if (/\.tfstate(\.backup)?$/.test(base)) return "json-keys";
  // JSON with comments (`opencode.jsonc`, 2026-10-22): the JSON reading,
  // whose key rules and comment grammar already read a JSONC text.
  if (/\.jsonc$/i.test(base)) return "json-keys";
  if (/\.(ya?ml)$/i.test(base)) return "yaml-keys";
  if (/\.json$/i.test(base)) return "json-keys";
  return null;
}

/**
 * The secret spans of one file. Whole-file (no spans, shape null) when the
 * shape is unknown, the content is not text, or the file is too large.
 */
export function extractSecretSpans(
  path: string,
  content: string,
  opts: ExtractOptions = {},
): SecretExtraction {
  if (content.length === 0 || content.length > MAX_STRUCTURED_BYTES) return NONE;
  if (content.includes("\u0000") || content.includes("�")) return NONE;
  if (opts.extract) {
    const x = withCredentialBelt(extractByRegex(content, opts.extract), content, null);
    return opts.extract === DOCUMENT_TWIN_EXTRACT ? withDocumentNames(x, content) : x;
  }
  const shape = secretFileShape(path);
  const x = withCredentialBelt(withSettledParts(extractShape(path, content), content), content, shape === null ? null : COMMENT_GRAMMARS[shape] ?? null);
  return mcpConfigKindOf(path, content) === null ? x : withMcpWire(path, content, x);
}

/** A personal document's twin (DOCUMENT_TWIN_EXTRACT) with each span that
 *  holds a person's name marked (`SecretSpan.name`): its line's label and its
 *  own text read as a name (personal-documents.ts `documentNameField`). A
 *  span that merged others, or whose text is not the file's own, is never
 *  one. Pure. */
function withDocumentNames(x: SecretExtraction, content: string): SecretExtraction {
  if (x.spans.length === 0) return x;
  let any = false;
  const spans = x.spans.map((s) => {
    if (s.parts || s.encoded || content.slice(s.start, s.end) !== s.value || !documentNameField(documentLineLabel(content, s.start), s.value)) return s;
    any = true;
    return { ...s, name: true as const };
  });
  return any ? { ...x, spans } : x;
}

/** How one shape writes a comment, for the credential belt's bare-token pass
 *  (`commentBodies`, 2026-10-17): its markers; whether a comment may follow
 *  other text on its line (`trailing`); whether a marker after text needs a
 *  blank before it (`needSpace`, dotenv's and YAML's ` #`); the quotes inside
 *  which a marker is no comment, and those in which a backslash escapes the
 *  next character; YAML's `''` and its block scalars, whose lines are data. */
interface CommentGrammar {
  markers: readonly string[];
  trailing: boolean;
  needSpace: boolean;
  quotes: string;
  backslash: string;
  yaml?: true;
  /** A block comment's open and close (JSONC's slash-star pair), across lines. */
  block?: readonly [string, string];
}

/** Each shape's comment grammar. None for `xml-keys` and a user's `extract`
 *  regex. `.pgpass`, `.netrc`, `~/.ssh/config` and git's store have
 *  whole-line comments only (their readers take no inline comment). INI,
 *  `.npmrc` and `pip.conf` take `#` or `;` after a blank (configparser's
 *  inline prefixes, npm's `ini`); TOML a `#` anywhere outside a string;
 *  JSONC a `//` or a slash-star block outside a string. */
const COMMENT_GRAMMARS: Readonly<Record<string, CommentGrammar>> = {
  "dotenv": { markers: ["#"], trailing: true, needSpace: true, quotes: "'\"`", backslash: "'\"`" },
  "ini": { markers: ["#", ";"], trailing: true, needSpace: true, quotes: "'\"", backslash: "\"" },
  "toml": { markers: ["#"], trailing: true, needSpace: false, quotes: "'\"", backslash: "\"" },
  "yaml-keys": { markers: ["#"], trailing: true, needSpace: true, quotes: "'\"", backslash: "\"", yaml: true },
  "npmrc": { markers: ["#", ";"], trailing: true, needSpace: true, quotes: "'\"", backslash: "\"" },
  "pgpass": { markers: ["#"], trailing: false, needSpace: true, quotes: "", backslash: "" },
  "netrc": { markers: ["#"], trailing: false, needSpace: true, quotes: "", backslash: "" },
  "json-keys": { markers: ["//", "/*"], trailing: true, needSpace: false, quotes: "\"", backslash: "\"", block: ["/*", "*/"] },
  "ssh-config": { markers: ["#"], trailing: false, needSpace: true, quotes: "", backslash: "" },
  "pip-conf": { markers: ["#", ";"], trailing: true, needSpace: true, quotes: "'\"", backslash: "\"" },
  "git-credentials": { markers: ["#"], trailing: false, needSpace: true, quotes: "", backslash: "" },
};

/** One reading of a line from `from` under grammar `g`: where a comment
 *  starts (-1 for none), and whether a quote was still open at the line's
 *  end. With `quotes` off every quote is an ordinary character. A quote
 *  opens a string only where a value can start (the line's start, after a
 *  blank or one of `=:[{,(`), so `don't` in a plain value is no quote. */
function commentScan(line: string, g: CommentGrammar, from: number, quotes: boolean): { at: number; open: boolean } {
  let q: string | null = null;
  for (let i = from; i < line.length; i++) {
    const c = line[i]!;
    if (q !== null) {
      if (c === "\\" && g.backslash.includes(q)) { i++; continue; }
      if (c === q) {
        if (g.yaml && q === "'" && line[i + 1] === "'") { i++; continue; }
        q = null;
      }
      continue;
    }
    const before = i === 0 ? "" : line[i - 1]!;
    if (quotes && g.quotes.includes(c) && (i === 0 || /[\s=:[{,(]/.test(before))) { q = c; continue; }
    for (const m of g.markers) {
      if (!line.startsWith(m, i)) continue;
      const lead = line.slice(0, i).trim() === "";
      if (!lead && (!g.trailing || (g.needSpace && !/\s/.test(before)))) continue;
      return { at: i, open: false };
    }
  }
  return { at: -1, open: q !== null };
}

/** Where a comment starts on one line under grammar `g`, from `from`, or
 *  -1. A quote still open at the line's end (`NOTE= "abc # old …`, which the
 *  dotenv extractor reads as the value `"abc`) proves nothing: the line is
 *  read again with every quote an ordinary character, and a comment either
 *  reading finds counts (review of !1621, fail-closed: a reading that missed
 *  it left the token raw). Pure. */
function commentStart(line: string, g: CommentGrammar, from = 0): number {
  const r = commentScan(line, g, from, true);
  return r.open ? commentScan(line, g, from, false).at : r.at;
}

/** A YAML block scalar's indicator ending a line's content (`key: |`,
 *  `- >-`, `key: |2`): the lines after it, more indented, are its data. */
const YAML_BLOCK_INDICATOR_RE = /(?:^|[\s:])[|>][-+0-9]*\s*$/;

/**
 * The comment BODIES of a file under its shape's grammar, as `[start, end)`
 * after the marker and the blanks after it, in order: whole-line comments
 * and (where the shape has them) trailing ones (`DEBUG=1 # backup …`,
 * `host: db # old …`). A UTF-8 byte order mark before the first line is not
 * part of it. In YAML the lines of a block scalar (`key: |` and the more
 * indented lines under it) are data, a `#` there included. A JSONC block
 * comment is a body on each line it spans. A line whose quote is still open
 * at its end is read both ways (`commentStart`). Pure, linear.
 */
function commentBodies(content: string, g: CommentGrammar): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  const blanks = (line: string, j: number): number => {
    while (j < line.length && (line[j] === " " || line[j] === "\t")) j++;
    return j;
  };
  const body = (at: number, line: string, j: number, k: number): void => {
    if (j < k) out.push([at + j, at + k]);
  };
  let block = -1; // YAML: the indentation of the line that opened a block scalar
  let inBlock = false; // JSONC: inside a block comment
  for (let at = content.startsWith("\uFEFF") ? 1 : 0; at <= content.length; ) {
    const nl = content.indexOf("\n", at);
    const end = nl < 0 ? content.length : nl;
    const textEnd = end > at && content[end - 1] === "\r" ? end - 1 : end;
    const line = content.slice(at, textEnd);
    const indent = line.length - line.trimStart().length;
    if (g.yaml && block >= 0 && (line.trim() === "" || indent > block)) {
      // data of the block scalar
    } else {
      block = -1;
      let pos = 0;
      let first = -1;
      if (inBlock && g.block) {
        const close = line.indexOf(g.block[1]);
        body(at, line, blanks(line, 0), close < 0 ? line.length : close);
        if (close < 0) pos = line.length;
        else { inBlock = false; pos = close + g.block[1].length; }
      }
      while (pos < line.length) {
        const i = commentStart(line, g, pos);
        if (i < 0) break;
        if (first < 0) first = i;
        if (g.block && line.startsWith(g.block[0], i)) {
          const close = line.indexOf(g.block[1], i + g.block[0].length);
          body(at, line, blanks(line, i + g.block[0].length), close < 0 ? line.length : close);
          if (close < 0) { inBlock = true; break; }
          pos = close + g.block[1].length;
          continue;
        }
        let j = i;
        while (g.markers.some((m) => line.startsWith(m, j))) j += g.markers.find((m) => line.startsWith(m, j))!.length;
        body(at, line, blanks(line, j), line.length);
        break;
      }
      if (g.yaml && YAML_BLOCK_INDICATOR_RE.test(first >= 0 ? line.slice(0, first) : line)) block = indent;
    }
    if (nl < 0) break;
    at = nl + 1;
  }
  return out;
}

/** Each candidate range less the taken ranges, as the pieces that remain.
 *  Both lists are in ascending order and their ranges never overlap within
 *  one list; one sweep, linear in both (an agent-written file of many
 *  comment lines must not make it quadratic: `mandu why` runs it on demand).
 *  Pure. */
function freePieces(
  cands: ReadonlyArray<readonly [number, number]>,
  taken: ReadonlyArray<readonly [number, number]>,
): Array<Array<[number, number]>> {
  const out: Array<Array<[number, number]>> = [];
  let i = 0;
  for (const [a, b] of cands) {
    while (i < taken.length && taken[i]![1] <= a) i++;
    const pieces: Array<[number, number]> = [];
    let p = a;
    for (let j = i; j < taken.length && taken[j]![0] < b; j++) {
      if (taken[j]![0] > p) pieces.push([p, taken[j]![0]]);
      p = Math.max(p, taken[j]![1]);
    }
    if (p < b) pieces.push([p, b]);
    out.push(pieces);
  }
  return out;
}

/** More credential-shaped spans than this in one file: the whole-file twin
 *  (fail-closed: the detector stops counting there). */
const BELT_MAX_HITS = 1000;

/**
 * THE CREDENTIAL BELT of a structured twin (plan 10 §2.4, 2026-10-17). The
 * shape extractors mask what a program reads as a secret: a secret-named
 * key's value, a URL's password. A credential anywhere else in the file
 * stayed raw in the twin, and the twin is what every program is served and
 * Read shows: a commented-out old key (`# OLD_STRIPE_KEY=sk_live_…`) reached
 * the model whole, and since the value backstop matches only verbatim
 * bytes, `base64 ./.e*` or `cut -c9- ./.e*` (a command in a clean tree that
 * does not name the file) handed it over in a form nothing recognized. The
 * value backstop already held that key as a piece of the file
 * (egress-fingerprint.ts `valuePieces`); the generator did not.
 *
 * The belt masks, with the SAME detectors the value backstop uses for a
 * registered file's pieces (no fork):
 *   - every credential-shaped span `locateSecretShapes` finds anywhere in
 *     the file (a vendor key, a private key, a URL password, a credential
 *     assignment's value), comment or not;
 *   - in a comment, whole-line or trailing, read by the shape's own
 *     grammar (`COMMENT_GRAMMARS`, `commentBodies`: dotenv's and YAML's
 *     ` #` outside quotes and YAML block scalars, INI's and `.npmrc`'s ` #`
 *     or ` ;`, TOML's `#` and JSONC's `//` outside strings; a BOM before the
 *     first line set aside), every bare token that reads as a credential
 *     (`locateBareSecretTokens`): no program reads a comment, so masking a
 *     word there costs no parser anything.
 * Each becomes a span (field `cred.<NAME>` after the assignment right
 * before it, `# OLD_STRIPE_KEY=…`, else `cred.<kind>`, `cred.stripe_key`,
 * `cred.token`; review of !1621: a line number renamed it under a `values:`
 * entry whenever a line was added above), so the
 * registry mints it a field row of the file like any other value: the value
 * backstop, the egress substitution and a copy elsewhere in the file
 * (`twinNeedles`) treat it as one. A span in a comment line is `comment`:
 * bound nowhere unless a label's `values:` names it (an old key a program
 * never sends; current-bindings.ts). A belt span never cuts into a span the
 * shape found (only what the shape left raw is added), and a bare token
 * that overlaps a detector span keeps only what still reads as a credential
 * on its own (`OLD_STRIPE_KEY=` is no secret once its key is masked).
 *
 * Only a structured twin gets a belt (an extraction with a span, or an
 * exhaustive shape's own-text twin, which becomes structured if the belt
 * finds anything): a whole-file twin already hides everything. More than
 * `BELT_MAX_HITS` detector spans make the whole-file twin. Pure.
 */
function withCredentialBelt(x: SecretExtraction, content: string, grammar: CommentGrammar | null): SecretExtraction {
  if (x.shape === null || (x.spans.length === 0 && !shapeIsExhaustive(x.shape))) return x;
  const hits = locateSecretShapes(content, { maxHits: BELT_MAX_HITS });
  if (hits.length >= BELT_MAX_HITS) return NONE;
  // Comment bodies, whole-line and trailing, [start, end) after the marker.
  const comments = grammar === null ? [] : commentBodies(content, grammar);
  /** A span's field name: the name its line assigns right before it
   *  (`OLD_STRIPE_KEY=` gives `cred.OLD_STRIPE_KEY`), else its kind
   *  (`cred.stripe_key`, `cred.token`). Never its line number, so a line
   *  added above it does not rename it under a `values:` entry, and never a
   *  hash of the value (a short hash of a guessable secret is a check of a
   *  guess). Repeats are `__2`, `__3` in file order. */
  const nameOf = (a: number, kind: string): string => {
    const lineAt = content.lastIndexOf("\n", a - 1) + 1;
    const m = /([A-Za-z_][A-Za-z0-9_.-]*)["']?[ \t]*[:=][ \t]*["']?$/.exec(content.slice(lineAt, a));
    return `cred.${m ? m[1]!.replace(/[^A-Za-z0-9_]/g, "_") : kind}`;
  };
  const inComment = (a: number, b: number): boolean => {
    // The last comment body starting at or before `a` (bodies are in order).
    let lo = 0;
    let hi = comments.length - 1;
    let k = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (comments[mid]![0] <= a) { k = mid; lo = mid + 1; } else hi = mid - 1;
    }
    return k >= 0 && b <= comments[k]![1];
  };
  // A copy of a secret the shape found (`# rotated from <value>`) is the
  // renderer's: it writes that value's own token there (`twinNeedles`). Only
  // a text at least GLUED_REPEAT_MIN_LEN long can be in a belt span (the
  // shorter ones a glued word keeps; a belt span is 12+ characters).
  const repeats = new Map<string, string[]>();
  for (const sp of x.spans) {
    for (const t of [sp, ...(sp.parts ?? [])].flatMap((q) => (q.encoded ? [q.value, content.slice(q.start, q.end)] : [q.value]))) {
      if (t.length < GLUED_REPEAT_MIN_LEN) continue;
      const k = t.slice(0, GLUED_REPEAT_MIN_LEN);
      const list = repeats.get(k) ?? [];
      if (!list.includes(t)) list.push(t);
      repeats.set(k, list);
    }
  }
  /** `[p, q)` less every copy of a shape's secret wholly inside it. */
  const withoutRepeats = (p: number, q: number): Array<[number, number]> => {
    if (repeats.size === 0) return [[p, q]];
    const copies: Array<[number, number]> = [];
    for (let i = p; i + GLUED_REPEAT_MIN_LEN <= q; i++) {
      for (const t of repeats.get(content.slice(i, i + GLUED_REPEAT_MIN_LEN)) ?? []) {
        if (i + t.length <= q && content.startsWith(t, i)) copies.push([i, i + t.length]);
      }
    }
    return copies.length === 0 ? [[p, q]] : freePieces([[p, q]], copies)[0]!;
  };
  const add: SecretSpan[] = [];
  const keep = (cands: ReadonlyArray<{ start: number; end: number; kind: string }>, taken: ReadonlyArray<readonly [number, number]>, ok: (v: string) => boolean): void => {
    const pieces = freePieces(cands.map((c) => [c.start, c.end] as const), taken);
    cands.forEach((c, i) => {
      for (const [p, q] of pieces[i]!) {
        for (const [a, b] of withoutRepeats(p, q)) {
          const value = content.slice(a, b);
          // What a copy of a known secret leaves of a span (`<value>x`) is
          // kept only when it still reads as a credential of its own.
          const cut = a !== p || b !== q;
          if (!(cut ? looksLikeSecretValue(value) || locateSecretShapes(value).length > 0 : ok(value))) continue;
          const span: SecretSpan = { key: nameOf(a, c.kind), start: a, end: b, value };
          if (inComment(a, b)) span.comment = true;
          add.push(span);
        }
      }
    });
  };
  // The detector's spans less what the shape masked already (its parts lie
  // inside its spans); then the comments' bare tokens less both.
  const shapeTaken = x.spans.map((s) => [s.start, s.end] as const);
  keep(hits.map((h) => ({ start: h.start, end: h.end, kind: h.shape.replace(/-/g, "_") })), shapeTaken, (v) => /[A-Za-z0-9]/.test(v));
  const taken = [...shapeTaken, ...add.map((s) => [s.start, s.end] as const)].sort((a, b) => a[0] - b[0]);
  const tokens = comments.flatMap(([s, e]) => locateBareSecretTokens(content.slice(s, e)).map((t) => ({ start: s + t.start, end: s + t.end, kind: "token" })));
  keep(tokens, taken, looksLikeSecretValue);
  if (add.length === 0) return x;
  // Field names unique among the shape's spans and parts (`finish`'s `__n`).
  const names = new Set<string>();
  for (const s of x.spans) {
    names.add(s.key);
    for (const p of s.parts ?? []) names.add(p.key);
  }
  // The next number to try per name (one counter each: a file of 40,000
  // `cred.token` fields must not rescan from `__2` every time).
  const nextOf = new Map<string, number>();
  for (const s of add) {
    let key = s.key;
    let n = nextOf.get(s.key) ?? 2;
    while (names.has(key)) key = `${s.key}__${n++}`;
    nextOf.set(s.key, n);
    s.key = key;
    names.add(key);
  }
  return { shape: x.shape, spans: [...x.spans, ...add].sort((a, b) => a.start - b.start) };
}

/** `extractSecretSpans` by the path's shape, before `withSettledParts`. */
function extractShape(path: string, content: string): SecretExtraction {
  // MCP and editor configs (secret-discovery.md §2.10): the shape's reading
  // plus each server entry's values.
  const mcp = mcpConfigKindOf(path, content);
  if (mcp === "codex") return withoutMcpReferences(extractCodexToml(content));
  if (mcp !== null && secretFileShape(path) === "json-keys") {
    const entries = mcpServerEntries(path, content) ?? [];
    return withoutMcpReferences(extractJsonKeys(content, (keyed) => mcpEntrySpans(entries, keyed, "json-keys")));
  }
  // Goose's and Continue's YAML (2026-10-22): a server section this reader
  // cannot read in full makes the whole-file twin (the fail-safe, as an
  // unreadable Codex inline table does).
  if (mcp !== null && secretFileShape(path) === "yaml-keys") {
    const entries = mcpServerEntries(path, content);
    if (entries === null) return NONE;
    return withoutMcpReferences(extractYamlKeys(content, (keyed) => mcpEntrySpans(entries, keyed, "yaml-keys")));
  }
  switch (secretFileShape(path)) {
    case "dotenv": return extractDotenv(content, path.slice(path.lastIndexOf("/") + 1) === ".envrc");
    case "ini": return extractIni(content);
    case "toml": return extractToml(content);
    case "xml-keys": return extractXmlKeys(content);
    case "pgpass": return extractPgpass(content);
    case "netrc": return extractNetrc(content);
    case "npmrc": return extractNpmrc(content);
    case "yaml-keys": return extractYamlKeys(content);
    case "json-keys": return extractJsonKeys(content);
    case "ssh-config": return extractSshConfig(content, path);
    case "pip-conf": return extractPipConf(content);
    case "git-credentials": return extractGitCredentials(content);
    default: return NONE;
  }
}

/**
 * The commands an `~/.ssh/config` twin withholds (plan 10 §11.13.3), by
 * line and keyword only, for `mandu why` and the dashboard. Empty for any
 * other shape. Never carries a command's text.
 */
export function withheldCommands(path: string, content: string): Array<{ line: number; keyword: string }> {
  if (secretFileShape(path) !== "ssh-config") return [];
  return extractSecretSpans(path, content).spans
    .filter((s) => s.withheld !== undefined)
    .map((s) => ({ line: s.withheld!.line, keyword: s.withheld!.keyword }));
}

/**
 * The twin text: `content` with every span replaced by `tokenFor(span)`
 * (in the span's own encoding, `encodeToken`), and every OTHER occurrence
 * of a span's secret text outside the spans (a comment that repeats the
 * value, another key's value that equals it) replaced by the same token
 * (plan 10 §2.4, 2026-10-09; `repeatedSecretsMasked`). A span that merged
 * others (`SecretSpan.parts`) masks a copy of each of its parts' secrets
 * as that part's own token (`tokenFor(part)`), so `tokenFor` must answer
 * for the parts too (2026-10-10).
 * Spans are ascending and non-overlapping (guaranteed by `extractSecretSpans`).
 */
export function renderStructuredTwin(
  content: string,
  spans: readonly SecretSpan[],
  tokenFor: (span: SecretSpan) => string,
): string {
  const needles = twinNeedles(content, spans, tokenFor);
  let out = "";
  let at = 0;
  for (const s of spans) {
    const t = encodeToken(tokenFor(s), s.encoded);
    out += repeatedSecretsMasked(content.slice(at, s.start), needles) + (s.withheld ? withheldCommandTwin(s.withheld, t) : s.wrap ? `'${s.wrap.prefix}${t}${s.wrap.suffix}'` : t);
    at = s.end;
  }
  return out + repeatedSecretsMasked(content.slice(at), needles);
}

/** A secret text to find outside the spans, and what the twin writes there. */
interface TwinNeedle { text: string; token: string }

/** Below this length (the fingerprint floor, egress-fingerprint.ts
 *  `MIN_FINGERPRINT_LEN`) a repeated secret text is replaced only where it
 *  stands as a word of its own: a short value glued inside a longer word
 *  (`ab` in `CRAB_URL`, `1234` in `12345`) does not identify the value, and
 *  replacing it there would break the twin's keys and hand programs a
 *  broken value (`MODE=owlish` beside `DB_PASS2=owl`). Such a twin line is
 *  refused by the twin's release rules instead (egress-fingerprint.ts
 *  `holdsSecretText`, 2026-10-17), so no Read or `cat` releases it. */
const GLUED_REPEAT_MIN_LEN = 8;

/** The secret texts of `spans` and of their parts, longest first: each
 *  one's value (written back as the plain token) and, for an encoded one,
 *  the file's own text of it (written back as the token in that encoding).
 *  Empty texts and a text already claimed are left out; the spans claim
 *  before the parts, so a secret that has a placeholder of its own keeps
 *  that token. */
function twinNeedles(content: string, spans: readonly SecretSpan[], tokenFor: (span: SecretSpan) => string): TwinNeedle[] {
  const byText = new Map<string, string>();
  for (const s of [...spans, ...spans.flatMap((x) => x.parts ?? [])]) {
    const token = tokenFor(s);
    if (s.value !== "" && !byText.has(s.value)) byText.set(s.value, token);
    if (s.encoded) {
      const text = content.slice(s.start, s.end);
      if (text !== "" && !byText.has(text)) byText.set(text, encodeToken(token, s.encoded));
    }
  }
  return [...byText].map(([text, token]) => ({ text, token })).sort((a, b) => b.text.length - a.text.length);
}

const WORD_CHAR = /[A-Za-z0-9_]/;

/** `gap` (text between spans) with every occurrence of a needle replaced by
 *  its token, left to right, the longest needle at a position winning. A
 *  needle shorter than `GLUED_REPEAT_MIN_LEN` is replaced only where no word
 *  character is glued to a word character at either of its ends. Pure. */
function repeatedSecretsMasked(gap: string, needles: readonly TwinNeedle[]): string {
  if (needles.length === 0 || gap === "") return gap;
  type Hit = { start: number; end: number; token: string };
  const hits: Hit[] = [];
  for (const n of needles) {
    for (let i = gap.indexOf(n.text); i >= 0; i = gap.indexOf(n.text, i + 1)) {
      const end = i + n.text.length;
      if (n.text.length < GLUED_REPEAT_MIN_LEN) {
        const gluedBefore = i > 0 && WORD_CHAR.test(gap[i - 1]!) && WORD_CHAR.test(n.text[0]!);
        const gluedAfter = end < gap.length && WORD_CHAR.test(gap[end]!) && WORD_CHAR.test(n.text[n.text.length - 1]!);
        if (gluedBefore || gluedAfter) continue;
      }
      hits.push({ start: i, end, token: n.token });
    }
  }
  if (hits.length === 0) return gap;
  // Earliest first; at one position the longest (needles are longest first,
  // and the sort is stable).
  hits.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  let out = "";
  let at = 0;
  for (const h of hits) {
    if (h.end <= at) continue; // inside a replacement already made
    // A hit that overlaps the one before and runs past it: its token too,
    // so no byte of either secret stays.
    out += (h.start < at ? "" : gap.slice(at, h.start)) + h.token;
    at = h.end;
  }
  return out + gap.slice(at);
}

/** A token as a span of this encoding holds it in the twin (plan 10
 *  §11.13.1): the base64 of its UTF-8 bytes, or every character outside
 *  `A-Za-z0-9-_.!~*'()` percent-encoded (`encodeURIComponent`), or as is.
 *  The program's own decoding gives the token back. Pure. */
export function encodeToken(token: string, encoded: SecretSpan["encoded"]): string {
  if (encoded === "base64") return Buffer.from(token, "utf8").toString("base64");
  if (encoded === "percent") return encodeURIComponent(token);
  return token;
}

// ── environment variables (§11.4) ───────────────────────────────────────────

/** Names the launcher never masks (plan 10 §11.4):
 *   - the agent's own credentials, by name (the file rule's AGENT_LOGIN_FILES,
 *     restated for the environment; the file rule is keyed per launch since
 *     secret-discovery.md §1.10, this one is not yet, so another agent's key
 *     variable stays raw too): a masked agent key would leave the agent
 *     unable to authenticate; the model proxy is where that credential is used,
 *     outside the agent's world;
 *   - Mandu's own routing variables;
 *   - the agents' configuration switches (`CLAUDE_*`, `CODEX_*`), EXCEPT a name
 *     with a credential suffix: `CLAUDE_CODE_SKIP_BEDROCK_AUTH=1` is a switch,
 *     `CLAUDE_CODE_MESSAGING_TOKEN` is a credential.
 *  Until 2026-09-26 every `CLAUDE_*` / `CODEX_*` name was exempt, which left
 *  CLAUDE_CODE_MESSAGING_TOKEN raw (release checklist d9): the token a Claude
 *  Code session hands its child processes to authenticate on its local
 *  messaging socket (CLAUDE_CODE_MESSAGING_SOCKET). An agent launched from
 *  inside another Claude Code session inherits it, and whoever holds it can
 *  message that outer session: a credential for another process's control
 *  channel, which nothing under Mandu needs raw. It is masked like any
 *  `*_TOKEN` now.
 *
 *  A config switch is exempt from the NAME shapes only: one whose value is
 *  a key in a known format ({@link envValueCredentials}) is a credential,
 *  not a switch, and is masked (2026-10-09). The agent's own credentials
 *  and Mandu's routing are exempt from that too. */
const AGENT_CREDENTIAL_NAMES_RE =
  /^(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|ANTHROPIC_CUSTOM_HEADERS|CLAUDE_CODE_OAUTH_TOKEN|OPENAI_API_KEY|CODEX_API_KEY)$/;
const MANDU_ROUTING_RE = /^(MANDU_[A-Z0-9_]*|ARBITER_SOCK|EVENT_DIR)$/;
const AGENT_SWITCH_RE = /^(CLAUDE|CODEX)_[A-Z0-9_]*$/;
const CREDENTIAL_SUFFIX_RE = /(_TOKEN|_SECRET|PASSWORD|_PASSWD|_PASS|_PWD|_PAT|_KEY|_APIKEY|_CREDENTIALS?|_WEBHOOK(?:_URL)?)$/;

/** Exempt whatever its value holds: the agent's own login and Mandu's
 *  routing. */
function envNameAlwaysExempt(name: string): boolean {
  return AGENT_CREDENTIAL_NAMES_RE.test(name) || MANDU_ROUTING_RE.test(name);
}

/** An agent's configuration switch (`CLAUDE_CODE_SKIP_BEDROCK_AUTH`), not a
 *  credential by its name. */
function envAgentSwitch(name: string): boolean {
  return AGENT_SWITCH_RE.test(name) && !CREDENTIAL_SUFFIX_RE.test(name);
}

/** Is this variable name exempt from the env-var mask's NAME shapes? A
 *  switch among these is still masked when its value is a key in a known
 *  format (`envSecretSpan`). */
export function envSecretExempt(name: string): boolean {
  return envNameAlwaysExempt(name) || envAgentSwitch(name);
}

/** Variable names whose whole value is a secret. Broad on purpose; a false
 *  positive masks a value and the reply filter shows the human the real one.
 *  `PASSWORD$` takes libpq's `PGPASSWORD` as well as `DB_PASSWORD`; `_PWD$`
 *  takes `MYSQL_PWD` but not the shell's `PWD` / `OLDPWD`; `_PAT$` a
 *  personal access token (`GITHUB_PAT`); `^TF_TOKEN_` Terraform's per-host
 *  tokens (`TF_TOKEN_app_terraform_io`); `_WEBHOOK_URL$` and `_WEBHOOK$` a
 *  Slack or Discord webhook (`SLACK_WEBHOOK`, `DISCORD_WEBHOOK`, the names
 *  CI actions read), whose URL is the credential (2026-10-09, `_WEBHOOK$`
 *  2026-10-10; plan 10 §11.4). Not `_DSN`: a DSN with a password is a URL
 *  with one (masked by its value), and a Sentry DSN is meant to be public.
 *  Not a bare `_KEY`. A `_PWD$` name holding a directory stays raw
 *  ({@link envPwdDirectory}). */
export const ENV_SECRET_NAME_RE =
  /(_TOKEN$|^TOKEN$|^TF_TOKEN_|_SECRET(_|$)|^SECRET(_|$)|PASSWORD$|_PASSWD$|_PASS$|_PWD$|_PAT$|_API_KEY$|^API_KEY$|_APIKEY$|_ACCESS_KEY(_ID)?$|_PRIVATE_KEY$|_CLIENT_SECRET$|_AUTH$|_CREDENTIALS?$|_SESSION_TOKEN$|_SIGNING_KEY$|_WEBHOOK_SECRET$|_WEBHOOK(_URL)?$)/i;

/** Names whose value is a URL that is itself the credential (a webhook
 *  carries its secret in the path): masked whole, where any other URL with
 *  no password stays raw. */
const ENV_SECRET_URL_NAME_RE = /_WEBHOOK(_URL)?$/i;

/** The `_PWD` names that are a password whatever they hold: MySQL's
 *  (`MYSQL_PWD`) and SnowSQL's (`SNOWSQL_PWD`). */
const PWD_PASSWORD_NAME_RE = /^(MYSQL|SNOWSQL)_PWD$/i;

/** A directory: `/`, then only the characters a path is usually made of
 *  (letters and digits of any script, `_ . @ + ~ % = : , - /` and a space).
 *  A password with other punctuation (`/x9F!k`) is no directory. */
const DIRECTORY_VALUE_RE = /^\/[\p{L}\p{N}_.@+~%=:,\/ -]*$/u;

/**
 * A `*_PWD` variable that holds a directory a script saved, not a password
 * (2026-10-10, plan 10 §11.4): `HOST_PWD` (a docker-compose idiom),
 * `ORIG_PWD`, `CALLER_PWD`. True when the name matches the shapes only by
 * its `_PWD` ending (`DB_SECRET_PWD` says secret without it), is not one of
 * the known password names (`MYSQL_PWD` is masked whatever it holds) and
 * the value is an absolute path ({@link DIRECTORY_VALUE_RE}). The value
 * check runs before this, so a key in a known format inside it still masks
 * it. Pure.
 */
function envPwdDirectory(name: string, value: string): boolean {
  return /_PWD$/i.test(name) && !PWD_PASSWORD_NAME_RE.test(name) &&
    !ENV_SECRET_NAME_RE.test(name.slice(0, -"_PWD".length)) && DIRECTORY_VALUE_RE.test(value);
}

/** The content detector's formats an environment variable's VALUE is masked
 *  for whatever its name (secret-detectors.ts): each is a vendor's prefix or
 *  a key block, with the detector's own check. Left out: the
 *  `credential-assignment` rule (an entropy test, which takes a hash, a
 *  build id or a random-looking path), `url-password` (the URL rules of
 *  `envSecretSpan` judge URLs) and a lone AWS access key id (an identifier;
 *  taken only with a secret key beside it, below). */
const ENV_VALUE_SHAPES: ReadonlySet<SecretShape> = new Set<SecretShape>([
  "private-key", "github-token", "gitlab-token", "anthropic-key", "openai-key", "slack-token",
  "stripe-key", "google-api-key", "npm-token", "pypi-token", "huggingface-token", "aws-secret-key",
]);

/** A 40-character base64 run, the shape of an AWS secret access key. */
const AWS_SECRET_RUN_RE = /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g;

/** The longest line the content detector matches line by line
 *  (secret-detectors.ts `MAX_LINE`), and how much two windows of a longer
 *  line overlap: more than any vendor key is long, so every key lies whole
 *  in one window. */
const ENV_SCAN_WINDOW = 10_000;
const ENV_SCAN_OVERLAP = 1_024;

/**
 * Every shape the content detector finds in an environment value, a line
 * over its line limit included (2026-10-10). `locateSecretShapes` skips a
 * line longer than 10,000 characters (a minified bundle in a scan), which
 * left a key inside a long one-line value (a JSON config blob) raw: the
 * fail-open direction. Such a line is scanned here in overlapping windows
 * of that size. A hit that touches a window's cut edge (its start, past the
 * line's first window; its end, before the line's last) is dropped, since
 * the cut can fake the boundary a format checks; the overlap puts the same
 * key whole in the next or previous window. Pure.
 */
function locateEnvShapes(value: string): ShapeSpan[] {
  const out = locateSecretShapes(value);
  const seen = new Set(out.map((h) => `${h.shape}:${h.start}:${h.end}`));
  let start = 0;
  while (start <= value.length) {
    const nl = value.indexOf("\n", start);
    const end = nl < 0 ? value.length : nl;
    if (end - start > ENV_SCAN_WINDOW) {
      for (let s = start; ; s += ENV_SCAN_WINDOW - ENV_SCAN_OVERLAP) {
        const e = Math.min(s + ENV_SCAN_WINDOW, end);
        for (const h of locateSecretShapes(value.slice(s, e))) {
          if (h.shape === "private-key") continue; // matched over the whole value above
          if ((s > start && h.start === 0) || (e < end && h.end === e - s)) continue;
          const hit = { shape: h.shape, start: s + h.start, end: s + h.end };
          const key = `${hit.shape}:${hit.start}:${hit.end}`;
          if (!seen.has(key)) { seen.add(key); out.push(hit); }
        }
        if (e === end) break;
      }
    }
    if (nl < 0) break;
    start = nl + 1;
  }
  return out;
}

/** A private-key header, and the END line that closes its block. */
const ENV_KEY_BEGIN_RE = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g;
const ENV_KEY_END_RE = /-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g;
/** Key material right after the header: separators, RFC 1421 headers with
 *  no space in their value (an encrypted PEM's `Proc-Type: 4,ENCRYPTED`),
 *  then 40 or more base64 characters. Run on a copy whose `\n` escapes are
 *  line breaks and whose `\/` escapes are `/`. */
const ENV_KEY_BODY_RE = /^\s*(?:[A-Za-z-]+: \S*\s+)*[A-Za-z0-9+/=]{40,}/;

/**
 * Private-key blocks in the forms an environment value holds them besides
 * real lines (2026-10-10): a JSON string with `\n` escapes (a Google Cloud
 * service-account key in `GCP_SA_KEY`, `GOOGLE_CREDENTIALS_JSON`), and a
 * PEM flattened onto one line with spaces, as some CI systems store keys.
 * The content detector's key-block rule needs real line breaks after the
 * header. Each span runs from the header to its END line (the value's end
 * when there is none); offsets are the value's own. A header alone
 * (documentation) is no key. Pure.
 */
function envPrivateKeyBlocks(value: string): ShapeSpan[] {
  const out: ShapeSpan[] = [];
  ENV_KEY_BEGIN_RE.lastIndex = 0;
  for (let m = ENV_KEY_BEGIN_RE.exec(value); m !== null; m = ENV_KEY_BEGIN_RE.exec(value)) {
    const from = m.index + m[0].length;
    ENV_KEY_END_RE.lastIndex = from;
    const end = ENV_KEY_END_RE.exec(value);
    const body = value.slice(from, end === null ? value.length : end.index)
      .replace(/\\+[nrt]/g, "\n").replace(/\\+\//g, "/");
    const stop = end === null ? value.length : end.index + end[0].length;
    if (ENV_KEY_BODY_RE.test(body)) out.push({ shape: "private-key", start: m.index, end: stop });
    ENV_KEY_BEGIN_RE.lastIndex = stop;
  }
  return out;
}

/**
 * The keys in a known format inside an environment variable's value (plan 10
 * §11.4, 2026-10-09): the content detector's vendor formats, held to a
 * higher bar than a scan's, since a hit replaces the value a program reads.
 *   - A GitHub `gh?_` token of the classic layout counts only with GitHub's
 *     own checksum (`githubTokenChecksumOk`); `github_pat_` has none.
 *   - An OpenAI `sk-` key counts only by a prefix OpenAI alone uses
 *     (`sk-proj-`, `sk-svcacct-`, `sk-admin-`) or the `T3BlbkFJ` its keys
 *     carry: a bare `sk-` begins host names and words.
 *   - An AWS access key id (`AKIA…`, `ASIA…`) counts only with a secret key
 *     beside it: a 40-character base64 run with upper case, lower case and
 *     a digit (a git hash is lower-case hex), not a stand-in.
 *   - A private key counts in a JSON string's `\n` escapes or flattened onto
 *     one line too ({@link envPrivateKeyBlocks}, 2026-10-10).
 * A line of any length is checked ({@link locateEnvShapes}, 2026-10-10).
 * Never the entropy rule. Pure.
 */
export function envValueCredentials(value: string): ShapeSpan[] {
  const hits = locateEnvShapes(value);
  const out = hits.filter((h) => {
    if (!ENV_VALUE_SHAPES.has(h.shape)) return false;
    const v = value.slice(h.start, h.end);
    if (h.shape === "github-token" && /^gh[pousr]_[A-Za-z0-9]{36}$/.test(v)) return githubTokenChecksumOk(v);
    if (h.shape === "openai-key") return /^sk-(?:proj|svcacct|admin)-/.test(v) || v.includes("T3BlbkFJ");
    return true;
  });
  for (const id of hits.filter((h) => h.shape === "aws-access-key-id")) {
    for (const m of value.matchAll(AWS_SECRET_RUN_RE)) {
      const run = m[0];
      if (m.index! < id.end && m.index! + run.length > id.start) continue;
      if (/[a-z]/.test(run) && /[A-Z]/.test(run) && /[0-9]/.test(run) && !isStandIn(run)) {
        out.push(id, { shape: "aws-secret-key", start: m.index!, end: m.index! + run.length });
        break;
      }
    }
  }
  const blocks = out.filter((h) => h.shape === "private-key");
  for (const k of envPrivateKeyBlocks(value)) {
    if (!blocks.some((b) => k.start < b.end && k.end > b.start)) out.push(k);
  }
  return out;
}

/** The law's additions to / exemptions from the env-var mask (plan 10
 *  §11.4, `policy.yaml` `env:`): variable names or `PREFIX_*` patterns. */
export interface EnvSecretRules {
  readonly secrets?: readonly string[];
  readonly exempt?: readonly string[];
  /** The agent's own key variables (exact names) masked anyway: the launch
   *  holds an auth grant for each, so the model proxy puts the key back
   *  (agent-sign-in.md §3.8). Never a pattern, never from the law. */
  readonly agentKeys?: readonly string[];
}

/** `NAME` exactly, or a `*` glob over the identifier (`MYCO_*`, `*_PIN`). */
export function envNameMatches(pattern: string, name: string): boolean {
  if (!pattern.includes("*")) return pattern === name;
  const re = new RegExp(`^${pattern.split("*").map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("[A-Za-z0-9_]*")}$`);
  return re.test(name);
}

/**
 * Would a variable of this NAME be masked, value unseen? The names-only half
 * of `envSecretSpan` for `mandu doctor --secrets` (the dry run never sends
 * values): true when the shape or the law's `secrets` names it and neither
 * the built-in exemptions nor the law's `exempt` do. A URL-password value or
 * a key in a known format ({@link envValueCredentials}) can still mask a
 * name this says no to; a URL value with no password, or a directory under
 * a `*_PWD` name ({@link envPwdDirectory}), can leave a name this says yes
 * to unmasked. The dry run says so.
 */
export function envSecretNameMatches(name: string, rules: EnvSecretRules = {}): boolean {
  if (envSecretExempt(name)) return false;
  if ((rules.exempt ?? []).some((p) => envNameMatches(p, name))) return false;
  if ((rules.secrets ?? []).some((p) => envNameMatches(p, name))) return true;
  return ENV_SECRET_NAME_RE.test(name);
}

/** pip's environment variables that hold an index URL (pip reads
 *  `PIP_<OPTION>`). */
const PIP_INDEX_ENV_RE = /^PIP_(EXTRA_)?INDEX_URL$/;

/** `scheme://user:password@` anywhere in a value. */
const EMBEDDED_URL_PASSWORD_RE = /[a-z][a-z0-9+.-]*:\/\/[^:/@\s]+:[^@\s]+@/i;

/**
 * The secret span of ONE environment variable, or null when it is not a
 * secret: a name that matches the shape masks its whole value; any value
 * that is a URL with a password masks the password only (§11.4, §12.1),
 * unless a key in a known format sits elsewhere in it; any value that holds
 * a key in a known format ({@link envValueCredentials}) is masked whole
 * whatever its name, an agent's config switch included (2026-10-09). A
 * webhook variable (`*_WEBHOOK_URL`, `*_WEBHOOK`) is masked whole, URL or
 * not; a `*_PWD` variable holding a directory stays raw (`HOST_PWD`,
 * {@link envPwdDirectory}; 2026-10-10).
 * The law's `env:` section (`rules`) adds names (`secrets`, whole value)
 * and exempts names (`exempt`, which wins over the value check too); the
 * built-in exemptions (the agent's own credential, Mandu's routing) hold
 * whatever the law or the value says.
 *
 * pip's index variables (`PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, plan 10
 * §11.13.1, 2026-10-03) read like `pip.conf`'s index URLs: the password is
 * `encoded: "percent"` (the twin holds the percent-encoded token, which pip
 * decodes) and, on `http(s)://` with a plain host or a bracketed IPv6
 * literal (`indexWireHost`), marked `wire` to it,
 * `httpsOnly` unless the URL is `http://` (whose field is then
 * `<NAME>.password_http`).
 */
export function envSecretSpan(name: string, value: string, rules: EnvSecretRules = {}): SecretSpan | null {
  if (value === "") return null;
  // An agent key variable the launch granted (§3.8): its whole value, before
  // the exemption that otherwise keeps the agent's own key raw.
  if ((rules.agentKeys ?? []).includes(name) && AGENT_CREDENTIAL_NAMES_RE.test(name)) return { key: name, start: 0, end: value.length, value };
  if (envNameAlwaysExempt(name)) return null;
  if ((rules.exempt ?? []).some((p) => envNameMatches(p, name))) return null;
  const whole = (): SecretSpan => ({ key: name, start: 0, end: value.length, value });
  const keys = envValueCredentials(value);
  if (envAgentSwitch(name)) return keys.length > 0 ? whole() : null;
  const urlSecret = ENV_SECRET_URL_NAME_RE.test(name);
  if (URL_USERINFO_RE.test(value) && !urlSecret) {
    const span = urlPasswordSpan(name, value, 0)!;
    // A key elsewhere in the value (a query parameter): the whole value.
    if (keys.some((k) => k.start < span.start || k.end > span.end)) return whole();
    if (PIP_INDEX_ENV_RE.test(name)) {
      span.encoded = "percent";
      const plain = percentDecodeText(span.value);
      const m = /^(https?):\/\/[^/?#\s]*@([^/?#\s@]+)/i.exec(value);
      const host = m ? indexWireHost(m[2]!) : null;
      if (plain !== null) {
        span.value = plain;
        if (host !== null) {
          const httpsOnly = m![1]!.toLowerCase() === "https";
          span.wire = { host, scheme: "basic", httpsOnly };
          // The env row keeps no URL, so its FIELD says which scheme the
          // gate may put it back over (registry.ts `wireReleaseScheme`):
          // `.password` is https only, `.password_http` an http index's.
          if (!httpsOnly) span.key = `${span.key}_http`;
        }
      }
    }
    return span;
  }
  // A URL with a password that is NOT at the start (a list of URLs, as pip
  // splits `PIP_EXTRA_INDEX_URL` on whitespace; a flag before it): masked
  // whole, the fail-safe direction (found 2026-10-03, plan 10 §11.13.1; it
  // used to reach the agent raw).
  if (EMBEDDED_URL_PASSWORD_RE.test(value)) return whole();
  if ((rules.secrets ?? []).some((p) => envNameMatches(p, name))) return whole();
  if (keys.length > 0) return whole();
  if (!ENV_SECRET_NAME_RE.test(name)) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value) && !urlSecret) return null; // a URL with no password
  if (envPwdDirectory(name, value)) return null; // HOST_PWD=/home/u/proj: a directory
  return whole();
}

