/**
 * egress-fingerprint — the §4 verbatim-leak TRIPWIRE (confidentiality.md §4
 * "Defense-in-depth, not the mechanism").
 *
 * A PURE function, like decideDesymbolization and decideSessionEgress.
 *
 * ── WHAT THIS IS, AND — LOUDLY — WHAT IT IS NOT ─────────────────────────────
 *
 * The guarantee is the symbol: untrusted/secret content reaches no egress
 * except as an opaque `$MDU:*` token, gated per-symbol (decideDesymbolization)
 * and per-session (decideSessionEgress). This module is NOT that guarantee. It
 * is the cheap tripwire §4 asks for on top of it:
 *
 *   > outbound payloads are additionally scanned against fingerprints of secret
 *   > content … to cheaply catch verbatim leaks. Fingerprinting alone would be
 *   > detection (paraphrase evades it); under the watermark it is a tripwire,
 *   > not the guarantee.
 *
 * It catches exactly one shape the symbol gates are structurally blind to: a
 * RAW secret VALUE (no `$MDU:` token anywhere) sitting verbatim in an outbound
 * body, bound for a host that datum was never released to. That happens when a
 * secret was never symbolized (the §6 mislabel case, accepted as fail-silent)
 * or verbatim-copied by a subprocess the taint machinery did not cover. A
 * paraphrase carries neither symbol NOR the verbatim bytes, so this sees
 * nothing — which is precisely why it is a tripwire and the watermark is the
 * mechanism.
 *
 * ── FAIL DIRECTION ──────────────────────────────────────────────────────────
 *
 * A tripwire that fired on absence would break every benign request. This scan
 * only ever ADDS a block on a POSITIVE verbatim match; its own failure (an
 * arbiter miss, an empty secret set) is a no-op, because the load-bearing gates
 * it backs already fail closed. That is not a softening of the doctrine — the
 * doctrine covers the guarantee, and the guarantee is elsewhere.
 */

import type { ConfidentialityLevel } from "../symbol-table/confidentiality.js";
import { MDU_SYM_FORMAT } from "../symbol-table/symbol-format.js";
import { destinationIsBound } from "./session-egress.js";
import { entropy, locateSecretShapes, looksLikeSecretValue } from "./secret-detectors.js";
import { shortTokenValue, tokenOccurs } from "./credential-names.js";

/** One secret the arbiter can fingerprint against: its raw value, its level,
 *  and the destinations it is bound to (a bound host is not a leak). */
export interface SecretFingerprint {
  /** The symbol name, for the emitted event / audit (never the value). */
  symbol: string;
  value: string;
  level: ConfidentialityLevel;
  bindings: string[];
  /** Registered from a labelled file (registry.ts `isRegisteredFileRow`):
   *  its bare credential tokens are pieces too (plan 10 §11.15). */
  fileRow?: boolean;
  /** The file's structured twin, for its base row (registry.ts
   *  `registeredFileTwin`): a line it carries verbatim is no piece
   *  ({@link valueFingerprints}, plan 10 §11.8). */
  twin?: ValueTwin;
  /** A short password (2026-10-19, secret-discovery.md §2.9): a value under
   *  MIN_FINGERPRINT_LEN that the caller found to be a password's
   *  (prompt-filter/registered-values.ts `shortTokenRow`), fingerprinted
   *  as a whole token only (credential-names.ts `tokenOccurs`). */
  token?: boolean;
}

/** The structured twin (placeholder copy) of a registered file, as its base
 *  row renders it: the twin's text, and every secret text of the file (each
 *  field's value and the file's own spelling of it). Plan 10 §11.8. */
export interface ValueTwin {
  text: string;
  secrets: readonly string[];
  /** A personal document's twin (2026-10-19, secret-discovery.md §2.7, "A
   *  person's name"): the file's lines (trimmed) whose only secret is a
   *  person's name (`Holder: Alex Demo`), and those names. Such a line is
   *  no piece of the file's row unless it holds another secret text or
   *  piece: the name is no fingerprint (registry.ts `documentNameRows`),
   *  and the line's label is in the twin. */
  nameLines?: readonly string[];
  names?: readonly string[];
}

/** A tripwire hit: a secret value found verbatim in the egress body, bound for
 *  a host it was not released to. Carries the SYMBOL, never the value — the
 *  event this rides to the dashboard must not itself leak the secret. */
export interface FingerprintHit {
  symbol: string;
  level: ConfidentialityLevel;
  /** Where in the body it matched: `url` | `header` | `body`, for the audit. */
  where: string;
}

/**
 * The shortest secret value we will fingerprint. Below this a "verbatim match"
 * is dominated by coincidence (a 3-char token appears in half of all English
 * bodies), so scanning it would be a false-positive generator, not a tripwire.
 * Real credentials/keys/contract refs are far longer; the floor costs nothing
 * on the values that matter and removes the noise on the ones that don't.
 * One exception (2026-10-19, secret-discovery.md §2.9): a registered
 * PASSWORD of 6 or 7 characters that holds a letter and a digit or a mark
 * (`SecretFingerprint.token`, credential-names.ts `shortTokenValue`) is
 * fingerprinted too, matched only as a whole token (`tokenOccurs`), so a
 * short password copied verbatim onto the wire still trips.
 */
export const MIN_FINGERPRINT_LEN = 8;

/**
 * The shortest LINE of a multi-line secret we will fingerprint on its own
 * (confidentiality-plan-11 §8 row 1, found by the live drill 2026-09-27). A
 * labeled document can reach a program's output by a route the connect/open
 * guard never sees as an open of the file: `git diff` / `git show` of a copy
 * committed to the workspace's own repository reads it out of `.git/objects`,
 * and a diff prefixes every line, so the whole value never appears verbatim.
 * A line of the document does. The floor is higher than
 * MIN_FINGERPRINT_LEN because document lines are prose: a short line ("## Terms",
 * "}") recurs everywhere, while a 24-character line of a contract is as good as
 * a key. A coincidental match masks a harmless output (fail-closed), never the
 * reverse.
 */
export const MIN_LINE_FINGERPRINT_LEN = 24;

/** Every `$MDU:` symbol token, in the minting grammar (symbol-format.ts
 *  MDU_SYM_FORMAT.pattern, a field path included). */
const SYMBOL_TOKENS_RE = new RegExp(MDU_SYM_FORMAT.pattern.source, "g");

/**
 * A SYMBOL TOKEN IS NO FINGERPRINT (2026-10-08, confidentiality.md §4; plan
 * 10 §11.8). True when `text` holds at least one `$MDU:` token and no letter
 * or digit outside its tokens: a token on its own line (`$MDU:anymodel_Read
 * [2451]`), a few tokens with spaces or punctuation between them. Such a
 * text holds no secret byte: a token is the opaque handle the agent is shown
 * in place of the value, and the egress gate already gates each token on
 * its own row (desymbolized only where that row is bound). As a piece of
 * another row it made the tripwire block the very release the gate allowed:
 * Codex's `cat` of a labelled document's twin came back masked whole as a
 * new row whose value is the runtime head plus the twin's token, the
 * token's line (24 characters, the line floor) became a line piece of that
 * row, and a `curl --data-binary @file` of the twin to the file's own bound
 * host tripped on it (drill conf-bound-host-release, Codex 0.160,
 * 2026-10-08). Any letter or digit outside a token keeps the text a
 * fingerprint, so a line that carries secret bytes beside a token stays one.
 * Pure.
 */
export function symbolTokensOnly(text: string): boolean {
  if (!text.includes("$MDU:")) return false;
  const rest = text.replace(SYMBOL_TOKENS_RE, "");
  return rest.length !== text.length && !/[\p{L}\p{N}]/u.test(rest);
}

/** May `value` be fingerprinted WHOLE: at or above MIN_FINGERPRINT_LEN and
 *  not made of symbol tokens only ({@link symbolTokensOnly}). Pure. */
export function fingerprintableValue(value: string): boolean {
  return value.length >= MIN_FINGERPRINT_LEN && !symbolTokensOnly(value);
}

/** The lines of a multi-line secret value long enough to fingerprint alone
 *  (trimmed, deduplicated). Empty for a single-line value: the whole value is
 *  its own fingerprint. `from` (a line boundary, default 0) skips the lines
 *  before it: the agent runtime's own result head at the start of a whole
 *  tool result (agent-result-head.ts, plan 10 §11.14). The value still counts
 *  as multi-line when only its head is, so a one-line output after the head
 *  keeps its line. A line of symbol tokens only is none
 *  ({@link symbolTokensOnly}). Pure. */
export function lineFingerprints(value: string, from = 0): string[] {
  if (!value.includes("\n")) return [];
  const out = new Set<string>();
  for (const raw of (from > 0 ? value.slice(from) : value).split(/\r?\n/)) {
    const line = raw.trim();
    if (line.length >= MIN_LINE_FINGERPRINT_LEN && !symbolTokensOnly(line)) out.add(line);
  }
  return [...out];
}

/**
 * The shortest credential-shaped span of a registered value fingerprinted on
 * its own, and its entropy floor (plan 10 §11.15): the prompt floor of plan 15
 * §4.1 (the `credential-assignment` gate of secret-detectors.ts), so a span
 * the detectors find (a URL password may be 3 characters) never becomes a
 * common short string to match.
 */
export const MIN_SPAN_FINGERPRINT_LEN = 12;
export const MIN_SPAN_FINGERPRINT_ENTROPY = 3.0;

/**
 * Every PIECE of a registered secret value that is fingerprinted on its own,
 * besides the whole value (plan 10 §11.15). Pure.
 *
 *   - its long lines ({@link lineFingerprints}; `from` skips an agent
 *     runtime's own result head, §11.14), less the lines its file's own
 *     structured twin carries (`twin`, below);
 *   - the value without its final line terminator(s), when that differs and
 *     is at or above MIN_FINGERPRINT_LEN: a one-line secret file is stored
 *     with its `\n`, so `key=<it>;` in a later output did not carry it;
 *   - every credential-shaped span the detectors find in it
 *     (`locateSecretShapes`: a provider key, a private key, a URL password,
 *     a credential assignment's value), at or above MIN_SPAN_FINGERPRINT_LEN
 *     characters and MIN_SPAN_FINGERPRINT_ENTROPY bits a character: the
 *     secret of a short `API_KEY=…` inside a result masked whole, whose
 *     whole value (a Codex head's chunk id and wall time in it) never
 *     recurs and whose line is under the line floor.
 *
 * Only values already known to be secret are pieces: a short line that is
 * not credential-shaped is not one (the line floor stays 24 for prose).
 *
 * A TWIN LINE IS NO PIECE (plan 10 §11.8, 2026-10-05). `twin` is the
 * structured twin (placeholder copy) of the registered file this value is
 * the base row of (registry.ts `registeredFileTwin`). A line of the value
 * that is, trimmed, also a line of that twin, and that holds none of the
 * file's secret texts (`twin.secrets`) and none of the value's other pieces
 * (a credential-shaped span, a bare token), is dropped: the twin generator
 * kept it as it is and the agent is shown it in the twin anyway, so it holds
 * no secret byte. Before, a `.env`'s long comment line made every rendering
 * of its own twin "a registered line verbatim" and masked the agent's Read
 * whole. A secret text kept verbatim in the twin (a value repeated inside a
 * comment) keeps its line, and every other piece, the whole value and every
 * field row stay. No twin (an unstructured or document file): every line.
 * Likewise a bare token the twin shows as it is, holding no secret text
 * (`DATABASE_PORT=5432`, 2026-10-17). A twin line that still holds a secret
 * text (a short value glued inside a longer word) is no piece of the file
 * (as one it masked a `package.json` holding `NODE_ENV=development` beside a
 * `.env`'s `DB_PASS=dev`): the twin's own release rules refuse it instead
 * ({@link holdsSecretText}).
 */
export function valueFingerprints(value: string, from = 0, opts: { bareTokens?: boolean; twin?: ValueTwin; limits?: PieceLimits } = {}): string[] {
  return valuePieces(value, from, opts).pieces;
}

/**
 * The bound on one value's piece extraction (plan 10 §11.18). `scanChars`:
 * how much of the value (a binary value: of its printable strings) is
 * scanned; `pieces`: how many pieces are kept; `window`: the size of one
 * scanning window (the default {@link PIECE_WINDOW_CHARS}; Infinity = one
 * pass, the reference the windowed extraction is tested against). A value
 * cut at either bound is INCOMPLETE ({@link ValuePieces}): a piece past the
 * bound is unknown, and the arbiter fails closed on such a file (its
 * readers' output rule releases nothing, `callTaint`; a holder's copy of it
 * is not read raw, `decideSecretOpen`).
 */
export interface PieceLimits {
  scanChars: number;
  pieces: number;
  window?: number;
}

/** Plan 10 §11.18. 16 Mi characters scanned and 65,536 pieces kept: a dense
 *  1 MiB text file (one 40-character line after another) gives about 47,000
 *  pieces, so every file the self-registration took before (≤ 1 MiB) stays
 *  complete; measured (§11.18) at about 0.2 s to extract and 0.8 s to build
 *  its automaton, once per change of that file. */
export const DEFAULT_PIECE_LIMITS: PieceLimits = { scanChars: 16 * 1024 * 1024, pieces: 65_536 };

/** One scanning window of a large value (plan 10 §11.18): a value at most
 *  this long that is not binary is extracted in one pass, as before. */
export const PIECE_WINDOW_CHARS = 1024 * 1024;

/** How far back a window's span search reaches into the window before it,
 *  so a multi-line credential (a PEM private key) across a window boundary
 *  is found whole. A 16384-bit RSA key in PEM is under 13 KiB. */
const SPAN_OVERLAP_CHARS = 16 * 1024;

/** A value's pieces, and whether they are all of them (not cut at a bound). */
export interface ValuePieces {
  pieces: string[];
  complete: boolean;
}

/** git's binary test on a decoded value: a NUL in its first 8000 characters
 *  (a NUL byte decodes to U+0000). Pure. */
export function binaryValue(value: string): boolean {
  return value.slice(0, 8000).includes("\u0000");
}

/** Every run of characters that is neither printable ASCII nor a tab: what
 *  separates the strings of a binary value (what `strings` prints, one run a
 *  line). An invalid UTF-8 sequence decodes to U+FFFD and never swallows the
 *  ASCII byte after it, so the runs are the file's own printable bytes. */
const NON_PRINTABLE_RUN = /[^\x20-\x7e\t]+/g;

/**
 * {@link valueFingerprints} with its completeness (plan 10 §11.18). A value
 * that is neither binary nor longer than one window (nor the scan bound) is
 * extracted in one pass, exactly as before. Otherwise:
 *
 *   - a BINARY value (a NUL in its first 8000 characters) is first reduced
 *     to its printable strings, one a line (`strings`): each is then a line
 *     piece (24+ characters), and its bare tokens and credential-shaped
 *     spans are pieces as in any file. Before, its tokens were glued to the
 *     NUL bytes around them and no piece was ever printed;
 *   - the text is scanned window by window (each ending at a line break, or
 *     a token break when a window holds no line break), the span search
 *     reaching {@link SPAN_OVERLAP_CHARS} back into the window before, so a
 *     PEM key across a boundary is found whole; the pieces are the union of
 *     every window's;
 *   - past `limits.scanChars` characters, or `limits.pieces` pieces, the
 *     extraction stops: `complete` is false.
 *
 * Pure.
 */
export function valuePieces(value: string, from = 0, opts: { bareTokens?: boolean; twin?: ValueTwin; limits?: PieceLimits } = {}): ValuePieces {
  const limits = opts.limits ?? DEFAULT_PIECE_LIMITS;
  const window = limits.window ?? PIECE_WINDOW_CHARS;
  const binary = binaryValue(value);
  if (!binary && value.length - from <= Math.min(window, limits.scanChars)) {
    const all = onePassPieces(value, from, opts);
    return all.length <= limits.pieces ? { pieces: all, complete: true } : { pieces: all.slice(0, limits.pieces), complete: false };
  }
  let complete = true;
  let body = from > 0 ? value.slice(from) : value;
  if (body.length > limits.scanChars) { body = body.slice(0, limits.scanChars); complete = false; }
  if (binary) body = body.replace(NON_PRINTABLE_RUN, "\n");
  // A single-line value (no line break anywhere) has no line pieces: the
  // whole value is its own (lineFingerprints).
  const multiLine = binary || value.includes("\n");
  const twinLines = opts.twin ? new Set(opts.twin.text.split(/\r?\n/).map((l) => l.trim())) : null;
  const out = new Set<string>();
  let pos = 0;
  while (pos < body.length) {
    let stop = Math.min(body.length, pos + window);
    if (stop < body.length) {
      const nl = body.lastIndexOf("\n", stop - 1);
      if (nl >= pos) stop = nl + 1;
      else {
        // No line break in the window: end it at the last token break.
        let i = stop - 1;
        while (i > pos && !TOKEN_BREAK.test(body[i]!)) i--;
        if (i > pos) stop = i + 1;
      }
    }
    const win = body.slice(pos, stop);
    const tokens = opts.bareTokens ? withoutTwinTokens(bareSecretTokens(win), opts.twin) : [];
    const spans: string[] = [];
    const lead = Math.max(0, pos - SPAN_OVERLAP_CHARS);
    const spanText = body.slice(lead, stop);
    for (const s of locateSecretShapes(spanText)) {
      if (lead + s.end <= pos) continue; // wholly in the window before: found there
      const span = spanText.slice(s.start, s.end).trim();
      if (span.length >= MIN_SPAN_FINGERPRINT_LEN && entropy(span) >= MIN_SPAN_FINGERPRINT_ENTROPY) spans.push(span);
    }
    let lines: string[] = [];
    if (multiLine) {
      for (const raw of win.split(/\r?\n/)) {
        const line = raw.trim();
        if (line.length >= MIN_LINE_FINGERPRINT_LEN) lines.push(line);
      }
      if (twinLines && opts.twin) lines = withoutTwinLines(lines, opts.twin, [...tokens, ...spans]);
    }
    for (const p of [...lines, ...tokens, ...spans]) {
      out.add(p);
      if (out.size > limits.pieces) break;
    }
    if (out.size > limits.pieces) { complete = false; break; }
    pos = stop;
  }
  // Not for a binary value (its decoded text is no string a program prints)
  // nor one led by a runtime head (`valueFingerprints`).
  if (!binary && from === 0) {
    const trimmed = value.replace(/(?:\r?\n)+$/, "");
    if (trimmed !== value && trimmed.length >= MIN_FINGERPRINT_LEN) out.add(trimmed);
  }
  out.delete(value);
  const pieces = [...out].filter((p) => !symbolTokensOnly(p));
  return pieces.length <= limits.pieces ? { pieces, complete } : { pieces: pieces.slice(0, limits.pieces), complete: false };
}

/** One character that separates bare tokens ({@link TOKEN_SPLIT}). */
const TOKEN_BREAK = /[\s"'`,;()<>[\]{}|]/;

/** The one-pass extraction of {@link valueFingerprints} (a value of at most
 *  one window that is not binary). Pure. */
function onePassPieces(value: string, from: number, opts: { bareTokens?: boolean; twin?: ValueTwin }): string[] {
  // Plan 10 §11.15, case 1 (the maintainer, 2026-10-03): a row registered
  // from a labelled FILE also gives each bare token that reads as a
  // credential (`password Tq7vZ2pX9kLm` in a notes file has no shape the
  // detectors know). Never for an output row: its tokens are not known
  // secrets.
  const tokens = opts.bareTokens ? withoutTwinTokens(bareSecretTokens(value), opts.twin) : [];
  const spans: string[] = [];
  const body = from > 0 ? value.slice(from) : value;
  for (const s of locateSecretShapes(body)) {
    const span = body.slice(s.start, s.end).trim();
    if (span.length >= MIN_SPAN_FINGERPRINT_LEN && entropy(span) >= MIN_SPAN_FINGERPRINT_ENTROPY) spans.push(span);
  }
  let lines = lineFingerprints(value, from);
  if (opts.twin) lines = withoutTwinLines(lines, opts.twin, [...tokens, ...spans]);
  const out = new Set<string>(lines);
  for (const t of tokens) out.add(t);
  const trimmed = value.replace(/(?:\r?\n)+$/, "");
  // Not for a value led by a runtime head (`from` > 0): the head's chunk id
  // and wall time never recur, and its body alone is not a known secret.
  if (from === 0 && trimmed !== value && trimmed.length >= MIN_FINGERPRINT_LEN) out.add(trimmed);
  for (const s of spans) out.add(s);
  out.delete(value);
  // A symbol token is no piece (symbolTokensOnly): the value without its
  // final line terminator, when that is one token, included.
  return [...out].filter((p) => !symbolTokensOnly(p));
}

/** `lines` less each one its file's twin carries verbatim (trimmed) that
 *  holds none of `twin.secrets` and none of `pieces` (the value's other
 *  pieces). See {@link valueFingerprints}. Pure. */
export function withoutTwinLines(lines: readonly string[], twin: ValueTwin, pieces: readonly string[]): string[] {
  const twinLines = new Set(twin.text.split(/\r?\n/).map((l) => l.trim()));
  const held = [...twin.secrets, ...pieces].filter((t) => t !== "");
  // A line whose only secret is a person's name (ValueTwin.nameLines) is
  // judged by the file's OTHER secret texts and the value's pieces.
  const nameLines = new Set(twin.nameLines ?? []);
  const names = new Set(twin.names ?? []);
  const heldBesideNames = nameLines.size === 0 ? held : held.filter((t) => !names.has(t));
  return lines.filter((l) => (nameLines.has(l) ? heldBesideNames.some((t) => l.includes(t)) : !twinLines.has(l) || held.some((t) => l.includes(t))));
}

/** What separates the bare tokens of a labelled file: whitespace, quotes,
 *  brackets and list punctuation. `=`, `:`, `/`, `+`, `-`, `_`, `.` stay
 *  inside a token (a base64 or a dashed key keeps its own characters). */
const TOKEN_SPLIT = /[\s"'`,;()<>[\]{}|]+/;

/**
 * The bare tokens of a labelled file's value that read as credentials
 * (plan 10 §11.15, case 1): each token, its trailing sentence punctuation
 * dropped, that passes `looksLikeSecretValue` (12+ characters, a letter,
 * at least 3.0 bits a character, a digit or random-looking letters, not a
 * placeholder or stand-in). Prose, identifiers and placeholders never do.
 * Deduplicated, in order. Pure.
 */
export function bareSecretTokens(value: string): string[] {
  const out = new Set<string>();
  for (const s of locateBareSecretTokens(value)) out.add(value.slice(s.start, s.end));
  return [...out];
}

/** One run of characters {@link TOKEN_SPLIT} does not split. */
const TOKEN_RUN = /[^\s"'`,;()<>[\]{}|]+/g;

/**
 * {@link bareSecretTokens} by position: every bare token of `value` that
 * reads as a credential, as `[start, end)` (its trailing sentence
 * punctuation left out), in order, repeats included. The structured twin
 * generator masks these in a comment line (secret-extract.ts
 * `withCredentialBelt`, plan 10 §2.4, 2026-10-17), so the twin carries no
 * bare token this layer holds as a piece of the file. Pure.
 */
export function locateBareSecretTokens(value: string): Array<{ start: number; end: number }> {
  const out: Array<{ start: number; end: number }> = [];
  for (const m of value.matchAll(TOKEN_RUN)) {
    let start = m.index!;
    let run = m[0];
    // Right after an IPv6 literal's `]` (`@[::1]:8080/simple`: the brackets
    // split the URL), a `:port` is the address's, never a credential: judged
    // from after it, so `:8080/simple` is no piece of the file that would
    // trip on every request to that port and path (2026-10-17, plan 10
    // §11.13.1). A credential in the path after it is still judged.
    if (start > 0 && value[start - 1] === "]") {
      const port = /^:\d{1,5}/.exec(run);
      if (port) { start += port[0].length; run = run.slice(port[0].length); }
    }
    const t = run.replace(/[.:!?]+$/, "");
    if (t.length >= MIN_SPAN_FINGERPRINT_LEN && looksLikeSecretValue(t)) out.push({ start, end: start + t.length });
  }
  return out;
}

/**
 * Does `text` hold one of a registered file's secret texts outside its own
 * `$MDU:` tokens (a token holds no secret byte, though its hash or field may
 * spell a short value)? The structured twin's release rules refuse such a
 * text (claude-code-inbound.ts `isStructuredTwinText`,
 * `structuredTwinExecOutputPath`): a short value the generator left glued
 * inside a longer word (`MODE=owlish` beside `DB_PASS2=owl`) is in the twin,
 * and a rendering that carries it is no release (2026-10-17). Pure.
 */
export function holdsSecretText(text: string, secrets: readonly string[]): boolean {
  if (secrets.length === 0) return false;
  const bare = text.replace(SYMBOL_TOKENS_RE, "\u0000");
  return secrets.some((s) => s !== "" && bare.includes(s));
}

/** The bare tokens of `value` less each that is a whole line of its file's
 *  structured twin as it is (trimmed, an `export ` before it allowed) and
 *  holds none of the file's secret texts (2026-10-17, review of !1621): the
 *  same treatment a twin line gets ({@link withoutTwinLines}). A dotenv line
 *  `DATABASE_PORT=5432` is one bare token, and as a piece of the file it
 *  masked every Read and `cat` of the twin whole. A token that is only part
 *  of a twin line (`notes: Tq7vZ2pX9kLm`'s value) stays a piece, and so does
 *  one whose value part (after its first `=` or `:`) reads as a credential
 *  (`api_note=<32 hex>`, `REDIS_URL=redis://localhost:6379`). Pure. */
function withoutTwinTokens(tokens: readonly string[], twin: ValueTwin | undefined): string[] {
  if (!twin || tokens.length === 0) return [...tokens];
  const lines = new Set(twin.text.split(/\r?\n/).map((l) => l.trim().replace(/^export[ \t]+/, "")));
  // Second review of !1621: a value that itself reads as a credential stays
  // a piece (a labelled INI's `api_note=<32 hex>`, raw in the twin under a
  // key that does not look secret, the KNOWN LIMIT): its Read was masked
  // whole by this piece, and must stay so.
  const valueOf = (t: string): string => {
    const i = t.search(/[=:]/);
    return i < 0 ? "" : t.slice(i + 1);
  };
  return tokens.filter((t) => !lines.has(t) || holdsSecretText(t, twin.secrets) || looksLikeSecretValue(valueOf(t)));
}

/** Does `text` carry the secret: the whole value verbatim, or any of its
 *  pieces? `lines` is {@link valueFingerprints} (or, for the line rule alone,
 *  {@link lineFingerprints}) of the value (the caller caches it). Pure. */
export function secretValueMatch(text: string, value: string, lines: readonly string[]): "value" | "line" | null {
  if (fingerprintableValue(value) && text.includes(value)) return "value";
  for (const l of lines) if (text.includes(l)) return "line";
  return null;
}

/**
 * Scan one egress surface for verbatim secret leaks. Returns every secret whose
 * value appears in `text` AND whose bindings do NOT cover `destination` — a
 * secret at its own bound host is a release, not a leak. `public` secrets and
 * short values are skipped (see MIN_FINGERPRINT_LEN) but a short password,
 * matched as a whole token (`token`, §2.9); a multi-line secret also
 * matches on any of its long lines (MIN_LINE_FINGERPRINT_LEN) but those its
 * file's structured twin carries (`twin`, plan 10 §11.8), and every secret on
 * its pieces (`valueFingerprints`, plan 10 §11.15). A value or piece made of
 * symbol tokens only is no fingerprint ({@link symbolTokensOnly}): the
 * per-symbol gate judges each token on its own row. Pure + allocation-light:
 * a substring scan per secret, which is fine for the tripwire's small N.
 */
export function scanEgressFingerprint(
  surfaces: { where: string; text: string }[],
  secrets: SecretFingerprint[],
  destination: string,
): FingerprintHit[] {
  const hits: FingerprintHit[] = [];
  for (const s of secrets) {
    if (s.level === "public") continue;
    if (!s.value) continue;
    // A secret at a host it is bound to is a legitimate release, not a leak —
    // the per-symbol gate would have desymbolized it there too.
    if (destination && destinationIsBound(destination, s.bindings)) continue;
    if (s.value.length < MIN_FINGERPRINT_LEN) {
      // Under the floor: only a short password, as a whole token (§2.9).
      if (s.token !== true || !shortTokenValue(s.value, MIN_FINGERPRINT_LEN)) continue;
      const at = surfaces.find((surface) => surface.text && tokenOccurs(surface.text, s.value));
      if (at) hits.push({ symbol: s.symbol, level: s.level, where: at.where });
      continue;
    }
    // The whole value, or a long line of a multi-line secret (a labeled
    // document leaving as a diff or an excerpt: a program the agent runs can
    // hold a committed copy's bytes read out of .git/objects; see
    // MIN_LINE_FINGERPRINT_LEN), or another piece of it (plan 10 §11.15).
    const lines = valueFingerprints(s.value, 0, { bareTokens: s.fileRow === true, ...(s.twin ? { twin: s.twin } : {}) });
    for (const surface of surfaces) {
      if (surface.text && secretValueMatch(surface.text, s.value, lines) !== null) {
        hits.push({ symbol: s.symbol, level: s.level, where: surface.where });
        break; // one hit per secret is enough to trip
      }
    }
  }
  return hits;
}
